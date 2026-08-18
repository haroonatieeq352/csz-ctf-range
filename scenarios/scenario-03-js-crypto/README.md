# Scenario 03 — JavaScript Obfuscation & Single-Byte XOR

- **Port:** `8003`
- **Category:** Recon / Cryptography
- **Difficulty:** Easy
- **Flag:** `CTF{unus3d_v4r14bl3_l34k}`

## Walkthrough
1. Fetch `http://<host>:8003/main.js` and observe `window.__c = 'FgETLiA7ICZmMQojYSdkYTc5Zgo5ZmE+KA=='`.
2. Inspect `http://<host>:8003/js-config.json` -> observe `"dbg_key": 85`.
3. Base64-decode the token and XOR every byte with decimal `85`.
   - In Python: `bytes([b ^ 85 for b in base64.b64decode("FgETLiA7ICZmMQojYSdkYTc5Zgo5ZmE+KA==")]).decode()`
4. Result: `CTF{unus3d_v4r14bl3_l34k}`.
