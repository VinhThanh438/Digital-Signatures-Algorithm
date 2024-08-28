// Tạo khoá
const generateKeys = () => {
    // Chọn số nguyên tố p
    let L = 512; // Độ dài bit của p
    let p, q, h, g, x, y;

    do {
        p = generatePrime(L);
    } while (p < Math.pow(2, L - 1) || p >= Math.pow(2, L));

    // Chọn số nguyên tố q
    do {
        q = generatePrime(160);
    } while (q <= Math.pow(2, 159) || q >= Math.pow(2, 160));

    // Tìm h để g = h mod p > 1
    do {
        h = Math.floor(Math.random() * (p - 1)) + 1;
        g = modPow(h, (p - 1) / q, p);
    } while (g <= 1);

    // Chọn x ngẫu nhiên
    x = Math.floor(Math.random() * q);

    // Tính y = g^x mod p
    y = modPow(g, x, p);

    // Trả về khoá công khai và khoá riêng
    return {
        publicKey: { p, q, g, y },
        privateKey: x,
    };
};

// Tạo chữ ký số
const signMessage = (message, privateKey) => {
    let k, r, s;

    do {
        // Chọn k ngẫu nhiên
        k = Math.floor(Math.random() * privateKey.q);

        // Tính r = (g^k mod p) mod q
        r = modPow(privateKey.g, k, privateKey.p) % privateKey.q;
    } while (r === 0);

    // Tính s = (k^-1 * (SHA-1(M) + x * r)) mod q
    s =
        (modInverse(k, privateKey.q) * (sha1(message) + privateKey.x * r)) %
        privateKey.q;

    // Nếu s = 0, tạo lại chữ ký
    if (s === 0) {
        return signMessage(message, privateKey);
    }

    return { r, s };
};

// Kiểm tra chữ ký
function verifySignature(message, signature, publicKey) {
    const { r, s } = signature;

    // Kiểm tra tính hợp lệ của r và s
    if (r <= 0 || r >= publicKey.q || s <= 0 || s >= publicKey.q) {
        return false;
    }

    // Tính w = s^-1 mod q
    const w = modInverse(s, publicKey.q);

    // Tính u1 = (SHA-1(M) * w) mod q
    const u1 = (sha1(message) * w) % publicKey.q;

    // Tính u2 = (r * w) mod q
    const u2 = (r * w) % publicKey.q;

    // Tính v = ((g^u1 * y^u2) mod p) mod q
    const v =
        ((modPow(publicKey.g, u1, publicKey.p) *
            modPow(publicKey.y, u2, publicKey.p)) %
            publicKey.p) %
        publicKey.q;

    // Trả về true nếu v = r, false nếu không
    return v === r;
}

// Hàm trợ giúp
const generatePrime = (bits) => {
    // Tạo số ngẫu nhiên có độ dài bits
    let num =
        Math.pow(2, bits - 1) +
        Math.floor(Math.random() * (Math.pow(2, bits) - Math.pow(2, bits - 1)));

    // Kiểm tra số đó có là số nguyến tố không
    while (!isPrime(num)) {
        num += 2;
    }

    return num;
};

const isPrime = (n) => {
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 === 0 || n % 3 === 0) return false;

    let i = 5;
    while (i * i <= n) {
        if (n % i === 0 || n % (i + 2) === 0) {
            return false;
        }
        i += 6;
    }

    return true;
};

const modPow = (base, exponent, modulus) => {
    let result = 1;
    while (exponent > 0) {
        if (exponent % 2 === 1) {
            result = (result * base) % modulus;
        }
        exponent = Math.floor(exponent / 2);
        base = (base * base) % modulus;
    }
    return result;
};

function modInverse(a, m) {
    let m0 = m,
        t,
        q;
    let x0 = 0,
        x1 = 1;

    if (m === 1) {
        return 0;
    }

    while (a > 1) {
        q = Math.floor(a / m);
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) {
        x1 += m0;
    }

    return x1;
}

function sha1(message) {
    // Implement SHA-1 hash function here
    // (This is just a placeholder, you'll need to implement the actual SHA-1 algorithm)
    return message.length;
}
