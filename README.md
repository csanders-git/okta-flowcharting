# okta-flowcharting
A set of scripts designed to generate flowcharts to visually show Okta OIE Global Session Policies and Authentication Policies

# FAQ

Q: Why are you pickling results.

A: This is mostly a proof of concept and on large Okta tenants downloading this data can take a long time. As a reminder pickle is unsafe when accepting pickle files from untrusted sources (see https://davidhamann.de/2020/04/05/exploiting-python-pickle/)


Q: Why are you reading creds in from a file

A: Again, quick and dirty -- it didn't help that the Okta Python SDK was broken


Q: What is the cred file format?

A: A file named okta.creds with the following content.
```
{
    "orgUrl": "https://mydomain.okta.com",
    "token": "API key"
}
```
