# Password Security Checker

A simple web application built with **Flask** that allows users to check the strength and security of their passwords. Users can either upload a batch of passwords via a text file or enter a single password. The app evaluates password strength, calculates entropy, checks if the password has been leaked using the [Have I Been Pwned API](https://haveibeenpwned.com/), and suggests a secure alternative if needed.

## Features

- Check password strength based on length, character variety, and entropy.
- Detect if passwords have appeared in known data breaches using the HIBP API.
- Upload a text file containing multiple passwords or enter a single password.
- Generate secure password suggestions for weak or leaked passwords.
- Responsive and clean HTML interface.
