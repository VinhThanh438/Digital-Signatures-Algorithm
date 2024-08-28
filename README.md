# What is DSA?

    DSA is a cryptographic algorithm used to generate a digital signature for a given document. This signature serves as a secure, electronic fingerprint, uniquely identifying the signatory and verifying both the sender's identity and the document’s content. Introduced by the National Institute of Standards and Technology (NIST) in 1991, DSA became a critical part of the Digital Signature Standard (DSS).


# How Does DSA Work?

DSA works on a pair of keys: a private key and a public key. Here’s a simplified breakdown:

    1. Key Generation
        A user generates a private key, which is kept secret.
        A corresponding public key is generated, which can be shared openly.

    2. Signing Process
        The signatory uses their private key to sign a document, converting the document into a unique string of numbers.

    3. Verification Process
        The recipient uses the public key to verify the signature. If the numbers correspond correctly, the document is affirmed as authentic and unaltered.

> This dual-key system ensures that even if the public key is widely disseminated, only the private key holder can produce a valid signature.
