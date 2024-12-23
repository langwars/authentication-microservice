Notable things about Bun
---

1: Problem with b64.replace

```bash
TypeError: b64.replace is not a function. (In 'b64.replace(/\+/g, "-")', 'b64.replace' is undefined)
    at toBase64Url 
```

ChatGPT eventually replaced the crypto part with nodejs crypto.

---


2: Problem with not understanding that the Delete endpoint should have an HTTP method of DELETE.

I had to manually ask it to use the delete post method.

---

3: Erroneous performance

Even though a lot of people suggest running bun with the `--bun` flag, the command: `bun bun.js` slightly outperformed the command: `bun run --bun bun.js` in almost all scenarios. I suspect that it is related to the inclusion of `node:crypto`.