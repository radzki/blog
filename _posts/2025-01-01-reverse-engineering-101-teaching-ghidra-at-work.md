---
layout: post
title: "Reverse Engineering 101: Teaching Ghidra at Work"
description: "A beginner-friendly introduction to reverse engineering I prepared for my company's offsite learning lab"
date: 2025-01-01
tags: [reverse-engineering, ghidra, teaching, workshop]
---

## Introduction

At my company's recent offsite, we had a "Learning Lab" session where anyone could teach their peers something new. I chose to introduce reverse engineering — specifically, how to analyze compiled binaries using tools like Ghidra.

This post is a cleaned-up version of the material I prepared. The full source code and binaries are available on [GitHub](https://github.com/radzki/reverse-engineering-101).

---

## What is Reverse Engineering?

Reverse engineering is the process of discovering how something works by analyzing its structure, function, and operation — without access to the original design documents or source code.

While the term often evokes images of hackers, it's actually a broad discipline:

- **Engineers** reverse engineer competitor products to understand design decisions
- **Archaeologists** reverse engineer ancient technologies
- **Mechanics** reverse engineer vintage car parts that are no longer manufactured
- **Security researchers** reverse engineer software to find vulnerabilities

The goal isn't necessarily to copy — it's to **understand**.

---

## A Quick Recap: From Source Code to Binary

When you compile a C program, several transformations happen:

```
Source Code (.c)
      ↓
  Preprocessing    →  Expands #include, #define
      ↓
  Compilation      →  Generates assembly (.s)
      ↓
  Assembly         →  Produces object code (.o)
      ↓
  Linking          →  Creates final executable
      ↓
   Binary
```

The resulting binary contains machine code — raw bytes that the CPU executes directly. The original variable names, comments, and high-level structure are **lost** in this process.

This is what makes reverse engineering challenging: we're working backwards from those raw bytes to understand the original programmer's intent.

---

## The Toolbox

Here are the essential tools for software reverse engineering:

| Tool                                                       | Purpose                                         |
| ---------------------------------------------------------- | ----------------------------------------------- |
| `strings`                                                  | Extract human-readable strings from binaries    |
| `objdump`                                                  | Disassemble binaries, show headers and sections |
| `strace`                                                   | Trace system calls made by a program            |
| `ltrace`                                                   | Trace library calls                             |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA's open-source reverse engineering framework |
| [IDA Free](https://hex-rays.com/ida-free)                  | Industry-standard disassembler (free version)   |

For this workshop, we focused on **static analysis** — examining binaries without executing them.

---

## The Approach

Reverse engineering is detective work. There's rarely one "correct" way to solve a problem. Common techniques include:

1. **Reconnaissance** — Run `strings`, `file`, and `objdump` to gather initial intel
2. **Static analysis** — Load the binary in Ghidra, identify interesting functions
3. **Pattern recognition** — Look for common constructs (string comparisons, authentication checks)
4. **Hypothesis testing** — Make educated guesses and verify them

The beauty of this field is that you can often achieve the same goal through completely different approaches — from brute forcing to binary patching.

---

## Workshop Challenge: Password Checker

For the hands-on portion, I created two simple password-checking binaries with intentional vulnerabilities.

### Challenge 1: The Basics

The first binary is straightforward. You don't even need Ghidra — just `strings`:

```console
$ strings first
Enter password:
correct_password_here
Access granted!
Access denied.
```

Sometimes the answer is hiding in plain sight.

### Challenge 2: A Bit More Interesting

The second binary requires actual analysis. In Ghidra, we can:

1. Find the `main` function
2. Locate the password validation logic
3. Understand the comparison being made

There are multiple ways to "solve" this one:

- **Patch the binary** — Modify the conditional jump to always succeed
- **Understand the algorithm** — Reverse the password derivation logic
- **Find the debug flag** — Some binaries have hidden backdoors

> 💡 Fun fact: There are over 25 billion valid passwords for the second challenge. The validation logic is intentionally flawed.

---

## Using Ghidra

For those new to Ghidra, here's a quick workflow:

1. **Create a new project** — File → New Project
2. **Import the binary** — File → Import File
3. **Analyze** — Let Ghidra auto-analyze (accept defaults)
4. **Navigate** — Use the Symbol Tree to find `main` or search for strings
5. **Decompile** — The decompiler window shows pseudo-C code

The decompiler output won't be perfect — variable names are generic (`param_1`, `local_10`), and some constructs may look odd — but it's usually enough to understand the logic.

---

## Key Takeaways

From the workshop, participants walked away with:

1. **Understanding the compilation pipeline** — Why reverse engineering is hard (information loss)
2. **Familiarity with basic tools** — `strings`, `objdump`, and Ghidra
3. **A methodology** — Reconnaissance → Analysis → Hypothesis → Verification
4. **Hands-on experience** — Actually cracking a password checker

Most importantly: reverse engineering is accessible. You don't need to be a wizard — just curious and methodical.

---

## Resources

- [Workshop Repository](https://github.com/radzki/reverse-engineering-101) — Source code and binaries
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) — NSA's reverse engineering framework
- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — MCP server for Ghidra (AI integration)
- [strings man page](https://linux.die.net/man/1/strings)
- [objdump man page](https://linux.die.net/man/1/objdump)
- [strace man page](https://linux.die.net/man/1/strace)

---

## Conclusion

Teaching this workshop reminded me why I got into this field in the first place. There's something deeply satisfying about taking apart a black box and figuring out how it works.

If you're curious about reverse engineering, start small. Grab a simple crackme, fire up Ghidra, and see what you can figure out. The skills transfer surprisingly well to debugging, security research, and understanding legacy systems.

The code for this workshop is [on GitHub](https://github.com/radzki/reverse-engineering-101) if you want to try it yourself.
