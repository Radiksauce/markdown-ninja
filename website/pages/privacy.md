---
date: 2025-01-01T06:00:00Z
title: "Privacy Policy - Markdown Ninja"
type: "page"
tags: ["docs"]
authors: ["Markdown Ninja"]
url: "/privacy"
---

Our servers are located in Europe.

All the data collected is the data that your enter in the input boxes, there is no tracking, no IP address collection, no "information sharing" with third parties (other than for processing payments).

[Stripe](https://stripe.com) is used for payment processing and storing billing information.


Markdown Ninja is 100% Open Source. In case of doubt about the collection and usage of data, feel free to read its source code: [https://github.com/bloom42-markdown-ninja](https://github.com/bloom42-markdown-ninja).



## Private analytics

One of the main values of Markdown Ninja is that you don't need to add external services that sell the data of your visitors: everything you need to grow your audience is built-in and carefuly designed to respect your visitors.

One of these features is private analytics: we have designed a privacy-first, cookie-less analytics solution so that websites publishers can know which pages are popular and where their audience come from, but cryptography prevent them from tracking individual visitors.

Here is how it works:
```
visitorID = truncate(BLAKE3_hash(IP address || metadata || unique salt), 16)
```

Thus, given an IP address, it's impossible to say which websites or pages that IP address has visited.
