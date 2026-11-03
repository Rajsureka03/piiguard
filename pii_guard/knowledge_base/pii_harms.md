# SSN
Title: Social Security Number
Why it matters: A Social Security Number is the master key to a person's financial identity in the United States. It cannot easily be changed, so once it leaks, the exposure is effectively permanent.
Consequences: Criminals can open credit cards, loans, and utility accounts in your name; file a fraudulent tax return to steal your refund; obtain medical care billed to you; or apply for government benefits as you. Recovery from SSN-based identity theft can take months or years and damages your credit score.
LLM-specific risk: Text typed into an AI chatbot may be stored in conversation logs, reviewed by people for safety or quality, used to train future models depending on settings, or exposed in a data breach or shared-link leak. You lose control of where the number goes once it leaves your device.
Safer alternative: Ask the question without the number. For example, "How do I find my SSN on a W-2?" works just as well as pasting the number itself. The AI never needs your actual SSN to answer a tax question.

# ITIN_EIN
Title: Tax Identification Number (ITIN / EIN)
Why it matters: ITINs and EINs identify individual taxpayers and businesses to the IRS. Like an SSN, they are used to verify identity on tax filings.
Consequences: A leaked tax ID can be used to file fraudulent returns, redirect refunds, impersonate a business to vendors or banks, and open business credit lines.
LLM-specific risk: Tax season is when people are most likely to paste tax documents into chatbots. Whole W-2s or 1099s can expose your tax ID, employer, income, and address in a single prompt.
Safer alternative: Describe the form and the box you are confused about ("Box 12 code DD on my W-2") instead of uploading or pasting the document.

# CREDIT_CARD
Title: Credit or Debit Card Number
Why it matters: A card number, especially with an expiration date and CVV, is enough to make online purchases.
Consequences: Unauthorized charges, drained debit accounts (debit fraud hits your cash directly), card cancellation and reissue, and time spent disputing charges. Card numbers are bought and sold in bulk on criminal marketplaces.
LLM-specific risk: People sometimes paste statements or receipts to ask about a charge. The full number is never needed for that question.
Safer alternative: Refer to the card by its last four digits only, or describe the charge (merchant, amount, date).

# BANK_ACCOUNT
Title: Bank Account or Routing Number
Why it matters: Account and routing numbers together let someone pull money through ACH transfers or write counterfeit checks.
Consequences: Unauthorized withdrawals, fraudulent checks, account takeover attempts, and targeted phishing that uses your real bank details to seem legitimate.
LLM-specific risk: Questions about direct deposit, transfers, or budgeting often include account numbers that are not needed for the answer.
Safer alternative: Say "my checking account at my bank" rather than giving the numbers.

# PASSWORD
Title: Password, Passcode, or PIN
Why it matters: A password is a direct credential. Anyone who sees it can log in as you.
Consequences: Account takeover, locked-out access, theft of funds, and spread to other accounts if the password is reused anywhere else.
LLM-specific risk: Pasting a password to ask "is this strong?" or while debugging a login means the credential now exists in someone else's logs.
Safer alternative: Ask about password rules in general, or test a made-up example with the same structure. Change any password you have already shared.

# PASSPORT
Title: Passport Number
Why it matters: A passport is a government-issued identity document accepted worldwide.
Consequences: Identity fraud, fake document creation, fraudulent travel bookings, and account verification abuse on services that accept passports for ID checks.
LLM-specific risk: Travel-planning and visa questions often include passport details that the AI does not need.
Safer alternative: Ask about the visa or travel rule using only your nationality and destination.

# DRIVERS_LICENSE
Title: Driver's License Number
Why it matters: A driver's license number is a widely accepted ID used for renting cars, opening accounts, and verifying age and identity.
Consequences: Fake IDs, fraudulent account openings, and traffic tickets or legal issues tied to your record.
Safer alternative: Ask about licensing rules for your state without including the number.

# DOB
Title: Date of Birth
Why it matters: Date of birth looks harmless on its own, but it is one of the most common identity-verification questions for banks, healthcare portals, and government services.
Consequences: Combined with a name and address, a date of birth makes identity theft and account recovery fraud much easier. It is a key piece in "fullz" (complete identity profiles) sold by criminals.
LLM-specific risk: Small details shared across many prompts can be pieced together into a complete profile.
Safer alternative: Share your age range ("I'm in my 60s") instead of your exact birth date.

# ADDRESS
Title: Home Address
Why it matters: A home address reveals where you physically live and is used to verify identity for mail, deliveries, and credit applications.
Consequences: Mail theft, change-of-address fraud, stalking or physical safety risks, and more convincing phishing or scam calls.
Safer alternative: Share only your city or state when location matters to the answer.

# PHONE
Title: Phone Number
Why it matters: Phone numbers are used for two-factor authentication and account recovery.
Consequences: SIM-swap attacks that hijack text-message codes, targeted scam calls and texts, and linking your identity across services.
Safer alternative: Leave your number out. The AI cannot call you anyway.

# EMAIL
Title: Email Address
Why it matters: Your email address is the login and recovery point for most of your accounts.
Consequences: Targeted phishing, spam, credential-stuffing attempts, and linking your identity across data breaches.
Safer alternative: Use a placeholder like "name@example.com" when asking for help writing emails or formatting.

# NAME
Title: Full Name
Why it matters: A name on its own is low risk, but it is the anchor that ties every other detail to a real person.
Consequences: When paired with a birth date, address, or ID number, a name makes it possible to impersonate you. A name plus an SSN is enough for many fraud attempts.
LLM-specific risk: Pairing your name with sensitive details in the same prompt links those details to you.
Safer alternative: Use a placeholder name ("Alex") when the actual name is not needed.

# MEDICAL
Title: Medical Record or Insurance ID
Why it matters: Medical identity data is valuable to criminals because it can be used to bill insurance and obtain care or prescriptions.
Consequences: Medical identity theft can corrupt your health records with someone else's conditions, which can be dangerous in an emergency, and leave you with bills for care you never received.
Safer alternative: Describe your plan type ("a PPO through my employer") rather than giving member or record IDs.

# GENERAL
Title: Why PII and AI chatbots don't mix
Why it matters: Information you type into an AI tool leaves your control. Depending on the provider and your settings, prompts may be retained, reviewed by humans, used for model training, or exposed through breaches, shared links, or browser extensions.
Aggregation risk: Individually harmless details (name, city, birthday, employer) can be combined into a full identity profile. This is called the mosaic effect.
Scam risk: Older adults and people handling taxes, retirement accounts, or benefits are frequent targets of identity-theft scams, and those are exactly the topics people bring to AI assistants.
Good habit: Before you hit send, ask "Does the AI need this exact detail to answer my question?" Usually it does not.
