
import {PrivateKey, key, Aes} from "../lib";
import dictionary from './dictionary_en';


// test 1
console.log("\nCreate AFT-address-private-legacy-short -  suggest_brain_key begin...\n");

//let seed = "THIS IS A TERRIBLE BRAINKEY SEED WORD SEQUENCE";
let suggest_brain_key = "123456789"; //key.suggest_brain_key(dictionary.en); // "nathan";
console.log("Suggest Brain Key:", suggest_brain_key, "\n");

let brain = key.normalize_brainKey(suggest_brain_key);
//console.log("\nBrain key:", brain);

let pkey = PrivateKey.fromSeed( brain );

//console.log("\nPrivate:", pkey.toBuffer());
//console.log("\nPrivate key:", pkey.toWif());
//console.log("Public key :", pkey.toPublicKey().toString(), "\t", pkey.toPublicKey().toPublicKeyString(), "\n");

let pubkey = pkey.toPublicKey().toPublicKeyString();
let address_strings = key.addresses(pubkey);
// console.log("\nAddress Strings :", address_strings, "\n");
console.error("\nCreate AFT-address-private-legacy-short -  suggest_brain_key end...\n=====: ", 
	brain, " -", pkey.toWif(), pkey.toPublicKey().toPublicKeyString(), address_strings[address_strings.length-1]);


// test 2
console.log("\nCreate AFT-address-private-legacy-short -  aes begin...\n");
let password_plaintext = "123456789";
let password_aes = Aes.fromSeed( password_plaintext );
console.log("\npassword_aes:", password_aes);
let encryption_buffer = key.get_random_key().toBuffer();
console.log("\nencryption_buffer:", encryption_buffer);
let encryption_key = password_aes.encryptToHex( encryption_buffer );
console.log("\nencryption_key: - encryptToHex - ", encryption_key);
let encryption_plainbuffer = password_aes.decryptHexToBuffer(encryption_key);
console.log("\nencryption_plainbuffer: decryptHexToBuffer - ", encryption_plainbuffer);

let local_aes_private = Aes.fromSeed( encryption_buffer );
console.log("\nlocal_aes_private:", local_aes_private);

let password_private = PrivateKey.fromSeed( password_plaintext );
let password_pubkey = password_private.toPublicKey().toPublicKeyString();
console.log("\npassword_pubkey:", password_plaintext, " - ", password_pubkey, "\n");


for(let i=0; i<5; i++) {
	let pkey = key.get_brainPrivateKey( brain, i );
	let pubkey = pkey.toPublicKey().toPublicKeyString();
	let address_strings = key.addresses(pubkey);
	console.error("\nCreate AFT-address-private-legacy-short -  get_brainPrivateKey \n=====: ", 
		brain, " -", pkey.toWif(), pkey.toPublicKey().toPublicKeyString(), address_strings[address_strings.length-1]);
}

console.error("\nCreate AFT-address-private-legacy-short -  aes end...\n");

