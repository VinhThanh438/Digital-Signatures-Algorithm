// tính mod nghịch đảo
const modInverse = (a, m) => {
    let m0 = m,
        t,
        q;
    let x0 = 0,
        x1 = 1;
    if (m === 1) return 0;
    while (a > 1) {
        q = Math.floor(a / m);
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
};

// tính mod
const modExp = (base, exp, mod) => {
    let result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 === 1) result = (result * base) % mod;
        exp = Math.floor(exp / 2);
        base = (base * base) % mod;
    }
    return result;
};

const sha1 = (message) => {
    const rotateLeft = (n, s) => {
        return (n << s) | (n >>> (32 - s));
    };

    const toHexStr = (n) => {
        let s = '',
            v;
        for (let i = 7; i >= 0; i--) {
            v = (n >>> (i * 4)) & 0x0f;
            s += v.toString(16);
        }
        return s;
    };

    let msg = unescape(encodeURIComponent(message));
    let msgLen = msg.length;

    let words = [];
    for (let i = 0; i < msgLen - 3; i += 4) {
        words.push(
            (msg.charCodeAt(i) << 24) |
                (msg.charCodeAt(i + 1) << 16) |
                (msg.charCodeAt(i + 2) << 8) |
                msg.charCodeAt(i + 3)
        );
    }
    let i;
    switch (msgLen % 4) {
        case 0:
            i = 0x080000000;
            break;
        case 1:
            i = (msg.charCodeAt(msgLen - 1) << 24) | 0x0800000;
            break;
        case 2:
            i =
                (msg.charCodeAt(msgLen - 2) << 24) |
                (msg.charCodeAt(msgLen - 1) << 16) |
                0x08000;
            break;
        case 3:
            i =
                (msg.charCodeAt(msgLen - 3) << 24) |
                (msg.charCodeAt(msgLen - 2) << 16) |
                (msg.charCodeAt(msgLen - 1) << 8) |
                0x80;
            break;
    }
    words.push(i);

    while (words.length % 16 !== 14) words.push(0);
    words.push(msgLen >>> 29);
    words.push((msgLen << 3) & 0x0ffffffff);

    const K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

    let H0 = 0x67452301;
    let H1 = 0xefcdab89;
    let H2 = 0x98badcfe;
    let H3 = 0x10325476;
    let H4 = 0xc3d2e1f0;

    for (let blockstart = 0; blockstart < words.length; blockstart += 16) {
        let W = words.slice(blockstart, blockstart + 16);

        for (let t = 16; t < 80; t++) {
            W[t] = rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
        }

        let a = H0;
        let b = H1;
        let c = H2;
        let d = H3;
        let e = H4;

        for (let t = 0; t < 80; t++) {
            let temp;
            if (t < 20) {
                temp = ((b & c) | (~b & d)) + K[0];
            } else if (t < 40) {
                temp = (b ^ c ^ d) + K[1];
            } else if (t < 60) {
                temp = ((b & c) | (b & d) | (c & d)) + K[2];
            } else {
                temp = (b ^ c ^ d) + K[3];
            }
            temp = (rotateLeft(a, 5) + temp + e + W[t]) & 0x0ffffffff;
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        H0 = (H0 + a) & 0x0ffffffff;
        H1 = (H1 + b) & 0x0ffffffff;
        H2 = (H2 + c) & 0x0ffffffff;
        H3 = (H3 + d) & 0x0ffffffff;
        H4 = (H4 + e) & 0x0ffffffff;
    }

    return (
        toHexStr(H0) + toHexStr(H1) + toHexStr(H2) + toHexStr(H3) + toHexStr(H4)
    );
};

// Khai báo tham số
// DSA Parameters (small values for simplicity; in real life, these should be much larger)
const p = 23; // A large prime
const q = 11; // A prime divisor of p-1
const g = 2; // Generator of the subgroup

// // Key Generation
const x = Math.floor(Math.random() * (q - 1)) + 1; // Private key
const y = modExp(g, x, p); // Public key

// Tạo khóa
const sign = (message) => {
    const k = Math.floor(Math.random() * (q - 1)) + 1;
    const r = modExp(g, k, p) % q;
    const kInv = modInverse(k, q);
    const h = parseInt(sha1(message), 16) % q;
    const s = (kInv * (h + x * r)) % q;
    return { r, s };
};

// Kiểm tra khóa
const verify = (message, signature) => {
    const { r, s } = signature;
    const w = modInverse(s, q);
    const h = parseInt(sha1(message), 16) % q;
    const u1 = (h * w) % q;
    const u2 = (r * w) % q;
    const v = ((modExp(g, u1, p) * modExp(y, u2, p)) % p) % q;
    return { check: v == r };
};

const createSignature = () => {
    const messageE = document.querySelector('.message1');
    const signatureE = document.querySelector('.signature1');
    const hash1 = document.querySelector('.hash1');
    const getMessage = messageE.value;

    const { r, s, hash } = sign(getMessage);
    const toString = `{${r}, ${s}}`;
    signatureE.value = toString;
    hash1.value = hash;
};

const checkMessage = () => {
    const messageE = document.querySelector('.message2');
    const signatureE = document.querySelector('.signature2');
    const hash2 = document.querySelector('.hash2');
    const rs = document.querySelector('.result');
    const getMessage = messageE.value;
    let getSignature = signatureE.value;
    getSignature = getSignature
        .replace('{', '{"r":')
        .replace(',', ',"s":')
        .replace('}', '}');

    // Chuyển đổi chuỗi JSON hợp lệ thành đối tượng
    let obj = JSON.parse(getSignature);

    const { check, hash } = verify(getMessage, obj);
    if (check) {
        rs.value = 'Chữ ký hợp lệ';
        hash2.value = hash;
    } else {
        rs.value = 'Chữ ký không hợp lệ';
        hash2.value = hash;
    }
};

const transfer = () => {
    const messageE1 = document.querySelector('.message1');
    const signatureE1 = document.querySelector('.signature1');
    const messageE2 = document.querySelector('.message2');
    const signatureE2 = document.querySelector('.signature2');
    messageE2.value = messageE1.value;
    signatureE2.value = signatureE1.value;
};

const saveFile = () => {
    const textInput = document.querySelector('.signature1');
    const textContent = textInput.value;

    if (textContent) {
        const blob = new Blob([textContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.download = './example.txt';
        link.href = url;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
};

const readTextFromFile = (check) => {
    if (check == 'message') {
        const fileInput = document.getElementById('file-input1');
        const file = fileInput.files[0];

        if (file && file.type === 'text/plain') {
            const reader = new FileReader();
            reader.onload = function (e) {
                document.querySelector('.message2').textContent =
                    e.target.result;
            };
            reader.readAsText(file);
        } else {
            alert('Vui lòng chọn một file .txt');
        }
    }
    if (check == 'signature') {
        const fileInput = document.getElementById('file-input2');
        const file = fileInput.files[0];

        if (file && file.type === 'text/plain') {
            const reader = new FileReader();
            reader.onload = function (e) {
                document.querySelector('.signature2').textContent =
                    e.target.result;
            };
            reader.readAsText(file);
        } else {
            alert('Vui lòng chọn một file .txt');
        }
    }
};

const readTextFromFile1 = () => {
    const fileInput = document.getElementById('file-input3');
    const file = fileInput.files[0];

    if (file && file.type === 'text/plain') {
        const reader = new FileReader();
        reader.onload = function (e) {
            document.querySelector('.message1').textContent = e.target.result;
        };
        reader.readAsText(file);
    } else {
        alert('Vui lòng chọn một file .txt');
    }
};

// Example usage
// const message = 'Hello, DSA!';
// const signature = sign(message);
// console.log('Signature:', signature);
// const isValid = verify(message, signature);
// console.log('Signature valid:', isValid);
