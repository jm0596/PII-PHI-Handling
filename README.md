# PII-PHI Handling — Techniques Practice Project

A hands-on Databricks project practicing the full toolkit for protecting **PII (Personally Identifiable Information)** and **PHI (Protected Health Information)** throughout the data lifecycle — from classifying and minimizing data at ingestion, through de-identification techniques (hashing, tokenization, suppression, generalization, encryption), to fine-grained access control (column masks, row filters) and secure deletion.

All work is done in Databricks notebooks using PySpark, Delta Lake, and Unity Catalog.

---

## Project Architecture

Everything lives in a dedicated `pii_demo` Unity Catalog catalog, which cleanly separates raw sensitive data from protected outputs and access-control logic:

| Schema | Purpose |
| --- | --- |
| `pii_demo.pii_source` | Raw, unmodified source data containing PII (simulated) |
| `pii_demo.pii_target` | Protected outputs — minimized, hashed, tokenized, generalized, encrypted tables and views |
| `pii_demo.access_control` | SQL functions used for decryption, column masking, and row filtering (governed separately) |

**Source datasets (1,000 rows each, simulated):**

* `customers` — customer_id, full_name, email, phone, ssn, date_of_birth, address, city, country
* `employees` — employee_id, name, email, department, age, salary, city, job_title
* `web_logs` — log_id, user_id, ip_address, device, location, search_query, timestamp

---

## Techniques Covered

### 01 — Catalog and Schema Setup ([01_Catalog_and_Schema_Setup](PII%20Handling/01_Catalog_and_Schema_Setup))
Creates the `pii_demo` catalog and the `pii_source` / `pii_target` schemas.

**Why it matters:** Every PII-handling strategy starts with isolation. A dedicated catalog lets you apply catalog-level governance (permissions, lineage, auditing) to sensitive data as a unit, and keeps raw PII physically separated from the protected tables that consumers actually use.

### 02 — Data Minimization ([02_Minimization](PII%20Handling/02_Minimization))
Reads the raw customers table and writes only the columns needed for analysis (`customer_id`, `city`, `country`) to `customers_minimized`, dropping all direct PII columns.

**Why it matters:** Data minimization is a core privacy principle (GDPR Art. 5, HIPAA minimum-necessary). If a column isn't required for the use case, it shouldn't be copied into the analytics layer at all — you can't leak what you never store. It is the cheapest and safest technique: remove risk at the source instead of protecting it downstream.

### 03 — Classify and Tag ([03_Classify_and_Tag](PII%20Handling/03_Classify_and_Tag))
Copies the source table to the target zone and uses Unity Catalog column tags to classify every column: `pii` = true/false, `pii_type` = direct/indirect, and a `classification` value (name, email, phone, ssn, dob, address, location).

**Why it matters:** You can't protect what you haven't classified. Tags make PII discoverable and machine-readable across the whole workspace — driving automated governance, audit reports, and policy enforcement. Note the **direct vs. indirect** distinction: an email directly identifies a person, while city or date of birth are quasi-identifiers that can re-identify a person when combined (see *linkage / re-identification attacks*).

### 04 — Hashing ([04_Hashing](PII%20Handling/04_Hashing))
Replaces PII values with fixed-length hashes using PySpark built-ins, deliberately varying the algorithm per column to practice each one: SHA-256 (full_name), MD5 (email), SHA-1 (phone), SHA-512 (ssn), SHA-384 (date_of_birth), SHA-224 (address). Non-PII columns (customer_id, country) pass through unchanged. Output: `customers_hashed`.

**Why it matters:** Hashing is irreversible pseudonymization — the same input always yields the same hash, so records remain joinable and distinct-countable without exposing the raw value. Key caveats practiced here: it's **deterministic** (vulnerable to dictionary/rainbow-table attacks on low-entropy values like names or cities), and weak algorithms (MD5, SHA-1) are collision-prone — real pipelines should salt values and use SHA-256 or above. Hashing is best for analytics that need consistency, not for high-security storage.

### 05 — Tokenization ([05_Tokenization](PII%20Handling/05_Tokenization))
Generates random UUID tokens for each distinct PII value (email, full_name, phone, date_of_birth, address) via a UDF, joins them back onto the customer records to produce `customers_tokenized`, and stores separate secured lookup tables (e.g. `email_token_lookup`) that map tokens back to original values.

**Why it matters:** Unlike hashing, tokens are **random and carry no derivation from the original value**, so they can't be reversed by brute force. Determinism comes from the lookup table instead of the algorithm — the same email always maps to the same token, so analytics still join correctly. This is the classic tokenization pattern used in payments (PCI DSS scope reduction): the tokenized table is safe to share broadly, while the lookup tables are locked down (separate schema, restricted grants) and only joined back under strict controls.

### 06 — Data Suppression ([06_Anonymization_Data_Suppression](PII%20Handling/06_Anonymization_Data_Suppression))
Creates a `customers_suppressed` view that exposes only `customer_id` and `country` — every PII attribute is suppressed (removed entirely) rather than transformed.

**Why it matters:** Suppression removes sensitive attributes completely when they add no analytical value. Because it's implemented as a **view**, the underlying PII never gets copied to another storage location, and the view can be shared with broad audiences while access to the base table stays restricted. Suppression (drop the attribute) vs. masking (partially hide the value) vs. minimization (never copy it at all) are complementary removal strategies at different layers.

### 07 — Categorical Generalization ([07_Anonymization_Generalization_CategoricalGeneralization](PII%20Handling/07_Anonymization_Generalization_CategoricalGeneralization))
Maps specific employee job titles to broader categories (e.g. "Software Engineer" → "Engineering", "Product Manager" → "Management") using a `CASE WHEN` expression, writing the result to `employees_categorical_generalized`.

**Why it matters:** Generalization trades precision for privacy — a value is replaced by a broader category it belongs to, so it's still analytically useful but no longer distinguishes individuals. With only a handful of job-title categories, employees can't be singled out by their title. The core tension is **utility vs. risk**: coarser categories protect more but aggregate away more signal. This is a building block of k-anonymity — each generalized record should be indistinguishable from at least k-1 others.

### 08 — Binning ([08_Anonymization_Generalization_Binning](PII%20Handling/08_Anonymization_Generalization_Binning))
Converts `date_of_birth` into an `age_range` column (Under 18, 18-25, 26-35, …, 66+) using `months_between` + `floor`, replacing the exact date, and writes `customers_binning` with the age distribution checked.

**Why it matters:** Binning is generalization applied to numeric/date values — an exact date of birth is a quasi-identifier, but "36-45" puts hundreds of people in the same bucket. It preserves age-based analytics (demographics, cohort analysis) while eliminating the precision needed to identify an individual. Bucket boundaries are a privacy/utility dial: wider bins = more privacy, less granularity.

### 09 — IP Address Truncation ([09_Anonymization_Generalization_TruncatingIPAddresses](PII%20Handling/09_Anonymization_Generalization_TruncatingIPAddresses))
Truncates each web-log IP address by zeroing the last octet (`188.113.24.239` → `188.113.24.0`) with a regex, writing `web_logs_ip_truncated`.

**Why it matters:** IP addresses are personal data under GDPR — they can identify a household or device. Truncating the last octet keeps the network-level information (geo/ISP analysis) while making the address no longer point to a unique device. This is a widely used technique in web analytics (Google Analytics does exactly this in the EU) and works well on free-text/IP fields where standard masking functions don't apply.

### 10 — Rounding ([10_Anonymization_Generalization_Rounding](PII%20Handling/10_Anonymization_Generalization_Rounding))
Rounds each employee `salary` down to the nearest 10,000 (`floor(salary/10000)*10000`) and writes `employees_rounded`.

**Why it matters:** Salary is sensitive (often confidential by contract, and a quasi-identifier). Rounding is generalization for continuous measures: exact compensation can single out an individual in a small team, but a 10k band hides the precise figure while salary-band analytics — ranges, distributions, pay-equity reporting — remain accurate.

### 11 — Encryption ([11_Encryption](PII%20Handling/11_Encryption))
Encrypts every PII column with `aes_encrypt` (AES-128, base64-encoded for readability) into `customers_encrypted`, decrypts with `aes_decrypt` for verification, and creates a governed `decrypt_pii` SQL function in `access_control` so only authorized users can reverse the encryption.

**Why it matters:** Unlike hashing and tokenization, encryption is **reversible with the key** — data stays fully intact but unreadable to anyone without it. This is the right technique when the business genuinely needs the raw value back (support agents, billing). Best practices demonstrated: the decryption logic is centralized as a UC function in a separately governed schema, so access to the function = access to the data, and the key would live in **Databricks Secrets / a KMS vault** in production (the demo hardcodes it only for practice — never do that for real).

### 12 — RBAC Column Masking ([12_RBAC_Column_Masking](PII%20Handling/12_RBAC_Column_Masking))
Creates masking functions (`mask_full_name`, `mask_email`, `mask_phone`, `mask_ssn`, `mask_dob`, `mask_address`, `mask_city`) that show the original value to the `admin` group (`is_account_group_member`) and masked values to everyone else (e.g. `XXX-XX-1234` for SSN), then attaches them with `ALTER COLUMN … SET MASK`.

**Why it matters:** Column masks are **policy-based, enforced by Unity Catalog at query time** — unlike hashing/encryption, the raw data is never transformed or copied; each user sees different output from the *same* table based on their group. There's no way around it, because the mask is injected into every query plan that touches the column. This is ideal for shared tables where analysts need partial visibility (last-4 SSN for support) while admins see full values.

### 13 — RBAC Row Filters ([13_RBAC_Row_Filters](PII%20Handling/13_RBAC_Row_Filters))
Creates a `country_filter` function (members of `manager` see all rows; everyone else sees only `country = 'India'`) and attaches it with `ALTER TABLE … SET ROW FILTER ON (country)`.

**Why it matters:** Row filters are column masking's complement — they hide entire **rows** based on who is querying. Combined, the two give cell-level access control from a single table without maintaining per-audience copies. Real-world uses: regional teams see only their region's customers, tenants see only their own data. Enforcement is automatic and invisible to the consumer's SQL.

### 14 — Deletion & Retention ([14_Delete](PII%20Handling/14_Delete))
Deletes an employee record with `DELETE`, verifies it's gone from the current version, inspects `DESCRIBE HISTORY`, sets `delta.deletedFileRetentionDuration` to 30 days, time-travels to the old version where the record still exists, and finally `VACUUM`s the table to make the deletion unrecoverable.

**Why it matters:** The last mile of PII handling is the **right to erasure** (GDPR Art. 17) — and Delta's time travel means a `DELETE` is not truly gone: the old data files remain on disk until vacuumed. This notebook demonstrates the full lifecycle: logical delete → audit via history → retention window tuning → physical removal via VACUUM. Understanding that time travel + retention duration directly control how long deleted PII remains recoverable is essential for meeting compliance deadlines.

---

## Technique Comparison

| Technique | Reversible? | Data altered? | Enforced by | Best for |
| --- | --- | --- | --- | --- |
| Minimization | No | Removed at copy time | Pipeline design | Columns not needed downstream |
| Tagging | N/A | No | Governance metadata | Discoverability, audit, policy |
| Hashing | No (salted: hard) | Replaced in target table | Pipeline | Joinable pseudonyms, dedup |
| Tokenization | Yes, via lookup | Replaced + lookup table | Separated access to lookups | Payments, reversible-but-controlled |
| Suppression | No | Hidden via view | View grants | Broad sharing of safe subsets |
| Generalization (07–10) | No | Coarsened in target | Pipeline | Analytics needing aggregates, not detail |
| Encryption | Yes, with key | Replaced in target | Key + decrypt function | When raw values must be recoverable |
| Column masks | Mask only, per user | No — applied at read time | Unity Catalog policy | Same table, different visibility per group |
| Row filters | N/A, per user | No — applied at read time | Unity Catalog policy | Region/tenant-scoped access |
| Deletion + VACUUM | No | Physically removed | Delta retention settings | Right to erasure |

---

## Key Takeaways

* **Defense in depth:** no single technique is enough — real pipelines combine minimization (don't carry what you don't need), de-identification for analytics, and RBAC enforcement for what must stay raw.
* **Privacy vs. utility is a dial, not a switch:** generalization width, mask formats, and rounding granularity all trade identifiability against analytical precision.
* **Transformed data (04–11) vs. policy-based control (12–13):** hashing/tokenization/encryption change the stored data once and everyone sees the same thing; masks and filters leave data intact and tailor every user's view at query time.
* **Deletion is physical only after VACUUM:** Delta time travel keeps deleted rows readable until retention expires — plan retention and vacuum schedules around your compliance SLAs.
* **Production hardening:** store encryption keys in Databricks Secrets, prefer salted SHA-256+ over MD5/SHA-1, and govern lookup/decrypt functions with strict grants.

---

## How to Run

Run the notebooks in order (01 → 14). Each notebook is self-contained against the `pii_demo` catalog:

1. `01` creates the catalog and schemas (run once).
2. `02`–`14` each read from `pii_demo.pii_source.*`, apply one technique, and write to `pii_demo.pii_target.*` (or attach a policy to it).
3. Notebooks 11–13 additionally use the `pii_demo.access_control` schema for governed functions.

> Notebooks 11, 12, 13, and 14 must be executed top-to-bottom — later cells depend on tables and functions created in earlier cells.