# Security Policy

## Reporting a vulnerability

If you find a security issue in Chainmail (for example a crafted `.sol` file that makes the
parser hang or crash, or a problem in the generated HTML report), please don't open a public issue.

Use GitHub's private reporting instead: **Security** tab -> **Report a vulnerability**.

Please include:

- what the problem is and its impact
- steps or a minimal file to reproduce it
- the Chainmail version (`chainmail --version`) and Python version

I'll reply as soon as I can and keep you updated until it's fixed.

## Supported versions

Only the latest version on `main` gets security fixes.

## Scope

Chainmail only reads source files, it does not compile or execute contract code.
Findings reported by Chainmail about *your* contracts are not vulnerabilities in Chainmail itself.
