// Copyright 2015-2016, Google, Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
 
'use strict';
 
var express = require('express');
 
var app = express();
 
var sha1=require('sha1');
 
var INPUT_SIZE = 16;
 
function hexStringToByteArray(hexString) {
    // Make sure we have enough inputs to calculate this
    var hexStringMinLength = INPUT_SIZE * 2;
 
    if ((typeof hexString == "undefined") || (hexString.length < hexStringMinLength)) {
        return {};
    }
 
    // Parse the inputs into a byte array
    var result = new Array(INPUT_SIZE);
    for (var byte=0; byte < INPUT_SIZE; byte++) {
        result[byte] = parseInt(hexString.substring(byte * 2, (byte + 1) * 2), 16);
    }
 
    return result;
}
 
function byteArrayToHexString(byteArray) {
    var result = "";
 
    for (var byte=0; byte < byteArray.length; byte++) {
        result += byteArray[byte].toString(16);
    }
 
    return result;
}
 
 
// Verify - check if this is the correct key for this userID
// Key string format is: "00aabbddcc11ee4400aabbddcc11ee44" (16x2=32 characters, no spaces or commas, no "0x" in the beginning)
function verifyKey(userid, difficulty, keyString) {
 
    // Convert the provided key string into a byte array.
    var keyByteArray = hexStringToByteArray(keyString);
 
    if (keyByteArray.length != INPUT_SIZE) { // parsing failure
        return false;
    }
 
    // Generate the key appropriate for this userid
    var userKey = getKeyForUser(userid, difficulty);
 
    // Compare it to the key we were provided (while resisting side channel)
    var keyIsCorrect = true;
    for (var byte=0; byte<INPUT_SIZE; byte++) {
        if (userKey[byte] != keyByteArray[byte]) {
            keyIsCorrect = false;
        }
    }
 
 
    return keyIsCorrect;
}
 
// Hamming Weight of a variable
function hammingWeight(value) {
    // Case the value to unsigned int
    var valueAsInt = value | 0;
    var result = 0;
 
    // While the value is non-zero
    while (valueAsInt != 0) {
        // store its LSB
        result = result + (valueAsInt & 1);
 
        // Shift it to the right (zero fill so negative numbers don't crash us)
        // https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Bitwise_Operators#Unsigned_right_shift
        valueAsInt = valueAsInt >>> 1;
    }
 
    // answer the result
    return result;
}
 
// AES SubBytes
// Source:
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* AES implementation in JavaScript                                   (c) Chris Veness 2005-2016  */
/*                                                                                   MIT Licence  */
/* www.movable-type.co.uk/scripts/aes.html                                                        */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]
var AesSBox =  [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
                0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
                0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
                0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
                0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
                0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
                0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
                0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
                0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
                0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
                0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
                0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
                0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
                0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
                0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
                0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
function subBytes(inByte) {
    return AesSBox[inByte & 0xff];
}
 
// Javascript random Gaussian noise, using the Box-Muller polar form
// Ref: http://www.design.caltech.edu/erik/Misc/Gaussian.html
function randomGaussian(mean, variance) {
    var x1, x2, w, y1, y2;
 
    do {
        x1 = 2.0 * Math.random() - 1.0;
        x2 = 2.0 * Math.random() - 1.0;
        w = x1 * x1 + x2 * x2;
    } while ( w >= 1.0 );
 
    w = Math.sqrt( (-2.0 * Math.log( w ) ) / w );
    y1 = x1 * w;
    y2 = x2 * w;
 
    // Both of these are Gaussian with mean 0 and variance 1, we only keep one.
    return (y1 * variance + mean);
 
 
}
 
function randomByteArray(length) {
    var result = new Array(length);
    for (var byte=0; byte<result.length; byte++) {
        result[byte] = Math.floor(Math.random() * 256) & 0xff;
    }
 
    return result;
}
 
// set of offsets unique to a user
var LEAK_COUNT = 128;
function leakOffsetsForUser(username, difficulty) {
    // Fetch an offset based on the hash of the userid
    var hashedUsername = sha1("no_secrets" + difficulty + username);
 
    // Return the numbers 0 to 127 shuffled with the hash as the seed
    return shuffledNumbersWithSeed(LEAK_COUNT, hashedUsername);
}
 
// GPT-generated seeded RNG
function mulberry32(seed) {
    return function () {
        seed |= 0;
        seed = (seed + 0x6D2B79F5) | 0;
        let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}
 
function shuffledNumbersWithSeed(count, seed) {
    // Generate a list of numbers from 0 to count
    var offsets = [...Array(count).keys()];
 
    // Use the hash as a seed
    var numericSeed = parseInt(seed.substring(0, 8), 16); 
    var rng = mulberry32(numericSeed);
 
    // Shuffle the list using Fisher-Yates and rng invoked with the seed
    for (var i = count - 1; i > 0; i--) {
        var j = Math.floor(rng() * (i + 1));
        [offsets[i], offsets[j]] = [offsets[j], offsets[i]];
    }
 
    return offsets;
}
 
 
 
// Generate noisy leaks for the first two rounds of AES
// Some of the leaks are bogus, depending on the userid??
function cryptAndLeak(userid, difficulty, plaintext) {
    // Generate a user-dependent key
    var key = getKeyForUser(userid, difficulty);
    // Generate an array of leaks (some bogus)
    var leaks = new Array(LEAK_COUNT);
    for (var byte=0; byte<leaks.length; byte++) {
        leaks[byte] = 0; // hammingWeight(Math.floor(Math.random() * 256) & 0xff);
    }
 
    var leakOffsets = leakOffsetsForUser(userid, difficulty);
 
    // Going to leak HW[K^P], and HW[S[K^P]]
    for (byte=0; byte < INPUT_SIZE; byte++) {
        leaks[leakOffsets[byte]] = hammingWeight(key[byte] ^ plaintext[byte]);
        leaks[leakOffsets[byte + INPUT_SIZE]] = hammingWeight(subBytes(key[byte] ^ plaintext[byte]));
    }
 
    // Now add random Gaussian noise to the leaks and quantize them
    for (byte=0; byte < leaks.length; byte++) {
        leaks[byte] = parseFloat((leaks[byte] + randomGaussian(0, difficulty)).toFixed(3));
    }
    return leaks;
}
 
function getKeyForUser(username, difficulty) {
  // Hash the username with a salt
  var hashedUsername = sha1("no_secrets" + difficulty + username);
 
    // Grab the first 16 bytes from the hash (SHA1 is 20 byte)
  // Use as an index into a secret list of passwords
    var keyBytes = new Array(16);
    for (var byte=0; byte < 16; byte++) {
        keyBytes[byte] = parseInt(hashedUsername.slice(byte * 2, byte * 2 + 2),16)
    }
  return keyBytes;
}
 
 
 
// [START hello_world]
// Say hello!
app.get('/verify', function(req, res) {
  // Default difficulty is 0
  if (req.query.difficulty == null) {
    req.query.difficulty = 0;
  } else {
    // parse it as floating point
    req.query.difficulty = parseFloat(req.query.difficulty);
  }
 
  // Make sure we have a user and a key
  if ((req.query.user != null) && (req.query.key != null)) {
 
    // call the key verification function
    var isKeyCorrect = verifyKey(req.query.user, req.query.difficulty, req.query.key);
 
    // Answer the result.
    if (isKeyCorrect) {
      res.status(200).send('1');
    } else {
        res.status(200).send('0');
    }
  } else { // we didn't get both user and key
    res.status(200).send('Usage: http://127.0.0.1:8080/verify?user=yos&difficulty=1&key=4b165f8317b1a0a0a623a09df78ceaaa');
  }
});
 
app.get('/encrypt', function(req, res) {
    // Default difficulty is 0
    if (req.query.difficulty == null) {
        req.query.difficulty = 0;
    } else {
        // parse it as floating point
        req.query.difficulty = parseFloat(req.query.difficulty);
      }
 
    // Make sure we have a user
    if (req.query.user != null) {
        // Generate a random plaintext
        var plaintext = randomByteArray(INPUT_SIZE);
 
        // Crypt and leak.
        var theLeaks = cryptAndLeak(req.query.user, req.query.difficulty, plaintext);
 
        res.status(200).send(JSON.stringify({plaintext: byteArrayToHexString(plaintext), leaks:theLeaks}));
 
 
        } else { // we didn't get  user
            res.status(200).send('Usage: http://127.0.0.1:8080/encrypt?user=yos&difficulty=1');
        }
        });
 
app.get('/', function(req, res) {
        res.status(200).send('Usage: <br/>http://127.0.0.1:8080/encrypt?user=yos&difficulty=1<br/>http://127.0.0.1:8080/verify?user=yos&difficulty=1&key=4b165f8317b1a0a0a623a09df78ceaaa');
        });
 
// [END hello_world]
 
if (module === require.main) {
  // [START server]
  // Start the server
  var server = app.listen(process.env.PORT || 8080, function () {
    var host = server.address().address;
    var port = server.address().port;
 
    console.log('App listening at 127.0.0.1');
  });
  // [END server]
}
 
module.exports = app;