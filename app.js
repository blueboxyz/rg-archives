const SUPABASE_URL = 'https://skswsgdesyxsqwoptpvs.supabase.co'; 
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNrc3dzZ2Rlc3l4c3F3b3B0cHZzIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjUwNzI3NDUsImV4cCI6MjA4MDY0ODc0NX0.aaNW9_F8QCppubpa87RoiYDk8-kZK71nNmfrwACyT7g';
const supabase = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

let currentUserId = null;
let currentUsername = null;
let currentUserPrivateKey = null; // Stored locally, used for decryption
let activeSessionKey = null; // The shared K_AB for the current chat partner


/**
 * 1. Generates the user's permanent Private/Public key pair.
 * 2. Saves the Private Key securely (encrypted by the password) locally.
 * 3. Saves the Public Key to Supabase.
 */
async function generateAndStoreKeys(supabaseClient, userId, userPassword) {
    // 1. Generate the ECDH Key Pair
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256", // Standard curve for web cryptography
        },
        true, // Key is exportable
        ["deriveKey"]
    );

    // 2. Export the Public Key (The one we share)
    const publicKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.publicKey);
    // Convert to a base64 string for easy storage/transfer
    const publicKeyString = JSON.stringify(publicKeyJwk); 

    // 3. Export the Private Key (The secret one)
    const privateKeyJwk = await window.crypto.subtle.exportKey("jwk", keyPair.privateKey);
    const privateKeyString = JSON.stringify(privateKeyJwk);

    // 4. Secure Private Key Storage (CRITICAL STEP)
    // In a real app, you would encrypt the 'privateKeyString' using a key derived 
    // from the 'userPassword' (via a library like Argon2) before saving it to 
    // secure local storage (IndexedDB). For this simple example, we skip the 
    // password encryption layer, but remember it is VITAL for security.
    localStorage.setItem(`private_key_${userId}`, privateKeyString);

    // 5. Store the Public Key in Supabase (Step 1 from the previous section)
    const { error } = await supabaseClient
        .from('user_public_keys')
        .insert({ user_id: userId, public_key: publicKeyString });

    if (error) throw new Error('Failed to store public key: ' + error.message);

    console.log("Public key stored and private key saved locally.");
}

/**
 * Derives a shared symmetric Session Key (K_AB) using ECDH.
 * The session key is used for fast AES encryption/decryption of messages.
 */
async function deriveSessionKey(supabaseClient, recipientId, privateKeyJwk) {
    // 1. Fetch the recipient's Public Key from Supabase
    const { data, error } = await supabaseClient
        .from('user_public_keys')
        .select('public_key')
        .eq('user_id', recipientId)
        .single();

    if (error || !data) throw new Error("Recipient's public key not found.");

    // 2. Import the keys into the Web Crypto API format
    const recipientPublicKeyJwk = JSON.parse(data.public_key);
    const importedPublicKey = await window.crypto.subtle.importKey(
        "jwk",
        recipientPublicKeyJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false, // Not extractable
        []
    );

    const importedPrivateKey = await window.crypto.subtle.importKey(
        "jwk",
        JSON.parse(privateKeyJwk),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveKey"]
    );

    // 3. DERIVE the Session Key (K_AB)
    const sessionKey = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: importedPublicKey, // Use recipient's Public Key
        },
        importedPrivateKey, // Use sender's Private Key
        { name: "AES-GCM", length: 256 }, // The key used for message encryption
        true, // Key is extractable (to be used by encrypt/decrypt functions)
        ["encrypt", "decrypt"]
    );

    return sessionKey;
}

/**
 * Encrypts a plaintext message using the shared session key.
 * Returns the ciphertext plus the Initialization Vector (IV).
 */
async function encryptMessage(sessionKey, plaintext) {
    // AES-GCM requires a unique Initialization Vector (IV) for every message
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encodedPlaintext = new TextEncoder().encode(plaintext);

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        sessionKey,
        encodedPlaintext
    );

    // Combine IV and ciphertext for storage/transmission
    return JSON.stringify({
        iv: Array.from(iv),
        ciphertext: Array.from(new Uint8Array(ciphertextBuffer))
    });
}

/**
 * Decrypts a ciphertext using the shared session key.
 */
async function decryptMessage(sessionKey, encryptedDataString) {
    const encryptedData = JSON.parse(encryptedDataString);
    const iv = new Uint8Array(encryptedData.iv);
    const ciphertext = new Uint8Array(encryptedData.ciphertext);

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        sessionKey,
        ciphertext
    );

    return new TextDecoder().decode(decryptedBuffer);
}

async function handleSignUp() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // TODO: 1. HASH THE PASSWORD USING A LIBRARY LIKE BCRYPT-TS
    // For now, let's assume 'passwordHash' is the securely hashed password
    const passwordHash = password; // <-- REPLACE THIS WITH SECURE HASHING!

    // Call your custom Supabase RPC for sign up
    const { data, error } = await supabase.rpc('create_anonymous_user', {
        input_username: username,
        input_password_hash: passwordHash
    });

    if (error) {
        alert('Sign up failed: ' + error.message);
        return;
    }

    // 2. SUCCESS! Now generate and store the encryption keys
    currentUserId = data.user.id;
    currentUsername = data.user.username;
    
    try {
        await generateAndStoreKeys(supabase, currentUserId, password);
        alert('Sign up successful! Keys generated.');
        // Go to the chat screen
        // ...
    } catch (keyError) {
        alert('CRITICAL: Failed to generate/store keys: ' + keyError.message);
    }
}

/**
 * Handles sending a message: Encrypts the plaintext and sends the ciphertext to Supabase.
 */
async function sendMessage(recipientId) {
    const messageInput = document.getElementById('message-input');
    const plaintext = messageInput.value.trim();

    if (!plaintext || !activeSessionKey || !currentUserId) {
        console.error("Cannot send message: Missing text, session key, or user ID.");
        return;
    }

    try {
        // 1. Encrypt the plaintext message using the shared session key
        // (This uses the 'encryptMessage' function from Step 4)
        const encryptedDataString = await encryptMessage(activeSessionKey, plaintext);

        // 2. Insert the ciphertext into the public.messages table
        // RLS will ensure that currentUserId matches the sender_id.
        const { error } = await supabase
            .from('messages')
            .insert({
                sender_id: currentUserId,
                recipient_id: recipientId, // You need to define who the current recipient is
                ciphertext: encryptedDataString
            });

        if (error) throw new Error(error.message);

        console.log("Encrypted message sent successfully.");
        messageInput.value = ''; // Clear the input field

    } catch (error) {
        alert('Failed to send message securely: ' + error.message);
    }
}

/**
 * Sets up a Realtime subscription to listen for new messages addressed to the current user.
 */
async function subscribeToMessages() {
    // 1. Check for authenticated user and session key
    if (!currentUserId || !activeSessionKey) {
        console.error("Cannot subscribe: User not authenticated or session key not established.");
        return;
    }

    // 2. Listen for INSERT events where the recipient_id matches the current user's ID
    supabase
        .channel('chat-room')
        .on(
            'postgres_changes',
            { 
                event: 'INSERT', 
                schema: 'public', 
                table: 'messages',
                filter: `recipient_id=eq.${currentUserId}` // RLS also checks this, but filtering here reduces network traffic
            },
            async (payload) => {
                const messageData = payload.new;
                
                try {
                    // 3. Decrypt the received ciphertext
                    // (This uses the 'decryptMessage' function from Step 4)
                    const plaintext = await decryptMessage(activeSessionKey, messageData.ciphertext);

                    // 4. Display the plaintext message
                    displayMessage(messageData.sender_id, plaintext);

                } catch (error) {
                    console.error("Failed to decrypt message. Key mismatch or corrupted data.", error);
                    displayMessage(messageData.sender_id, "--- [DECRYPTION FAILED] ---");
                }
            }
        )
        .subscribe();
}

/**
 * A simple helper function to display the message in the UI.
 */
function displayMessage(senderId, content) {
    const messagesDiv = document.getElementById('messages');
    const messageElement = document.createElement('p');
    const senderTag = (senderId === currentUserId) ? 'You' : 'Partner';
    messageElement.textContent = `${senderTag}: ${content}`;
    messagesDiv.appendChild(messageElement);
    messagesDiv.scrollTop = messagesDiv.scrollHeight; // Scroll to bottom
}
