// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * RULE_WALLET_CLI_DETECTED, RULE_PRIVATE_KEY_MATERIAL, RULE_MNEMONIC_PHRASE
 *
 * Three rules that together detect AI-assisted crypto theft patterns.
 *
 * RULE_WALLET_CLI_DETECTED (HIGH)
 *   Fires when a bash command invokes a known wallet key-generation CLI
 *   (e.g. solana-keygen, ethkey, bitcoin-cli wallet calls), a crypto wallet
 *   API method is detected in parameters, or generateWallet-style calls appear.
 *   Bash tool parameters are JSON-serialized so the command string is scanned.
 *
 * RULE_PRIVATE_KEY_MATERIAL (HIGH)
 *   Fires when a 256-bit (64-char) hex private key appears in labeled context
 *   inside any tool's parameters (e.g. private_key = "0xabcd...").
 *   Requires a label prefix to reduce false positives from SHA-256 hashes.
 *   Also fires on 0x-prefixed 64-char hex strings (Ethereum private key format).
 *
 * RULE_MNEMONIC_PHRASE (HIGH)
 *   Fires when a BIP-39 mnemonic seed phrase appears in labeled context
 *   (e.g. mnemonic: "abandon ability able ..."). Matches 12+ lowercase
 *   words after a seed/mnemonic label.
 *
 * Tier:     community
 * Severity: HIGH
 */

import type { RuleDefinition } from "../../types.js";

export const RULE_WALLET_CLI_DETECTED: RuleDefinition = {
  rule_id: "RULE_WALLET_CLI_DETECTED",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        // solana-keygen: Solana wallet key generation CLI.
        {
          regex: "\\bsolana-keygen\\b",
          type: "wallet-cli:solana-keygen",
        },
        // ethkey: Ethereum key generation tool (go-ethereum).
        {
          regex: "\\bethkey\\b",
          type: "wallet-cli:ethkey",
        },
        // bitcoin-cli with wallet sub-commands.
        {
          regex: "\\bbitcoin-cli\\s+(?:createwallet|getnewaddress|dumpprivkey|importprivkey)",
          type: "wallet-cli:bitcoin-cli",
        },
        // hdwallet-derive: BIP-39/44 HD wallet derivation tool.
        {
          regex: "\\bhdwallet-derive\\b",
          type: "wallet-cli:hdwallet-derive",
        },
        // eth-keygen: standalone Ethereum key generator.
        {
          regex: "\\beth-keygen\\b",
          type: "wallet-cli:eth-keygen",
        },
        // cast wallet: Foundry's cast CLI wallet sub-command.
        {
          regex: "\\bcast\\s+wallet\\b",
          type: "wallet-cli:cast-wallet",
        },
        // Crypto wallet API method calls that indicate key creation or enumeration.
        {
          regex: "\\b(?:generateWallet|createWallet|eth_accounts|getOrCreateWallet)\\b",
          type: "wallet-cli:crypto-api",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "wallet_generation",
  description_template:
    "Wallet key generation activity detected via {{tool_name}}: {{credential_types}}.",
};

export const RULE_PRIVATE_KEY_MATERIAL: RuleDefinition = {
  rule_id: "RULE_PRIVATE_KEY_MATERIAL",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        // Private key hex string in labeled context. Uses .{0,15} to bridge
        // the separator (colon, equals, JSON colon-quote) between label and
        // value, avoiding backslash-quote escaping issues in the pattern string.
        {
          regex: "(?:private[_-]?key|privkey|priv_key).{0,15}(?:0x)?[0-9a-fA-F]{64}",
          type: "private-key-hex",
        },
        // Ethereum-style private key: 0x followed by exactly 64 hex chars.
        // The 0x prefix distinguishes this from SHA-256 hashes in most contexts.
        {
          regex: "\\b0x[0-9a-fA-F]{64}\\b",
          type: "eth-private-key",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "wallet_generation",
  description_template:
    "Private key material detected in {{tool_name}} parameters: {{credential_types}}.",
};

export const RULE_MNEMONIC_PHRASE: RuleDefinition = {
  rule_id: "RULE_MNEMONIC_PHRASE",
  version: "1.0.0",
  tier: "community",
  event_types: ["tool.invoked"],
  conditions: [
    {
      type: "credential_match",
      patterns: [
        // BIP-39 mnemonic in labeled context. Uses .{0,20} to bridge the
        // separator between label and word sequence. Matches 12+ space-separated
        // lowercase words (the 12-word minimum = 128-bit BIP-39 entropy).
        {
          regex: "(?:mnemonic|seed.phrase|recovery.phrase).{0,20}(?:[a-z]+\\s+){11}[a-z]+",
          type: "bip39-mnemonic",
        },
      ],
    },
  ],
  severity: "HIGH",
  category: "wallet_generation",
  description_template:
    "BIP-39 mnemonic seed phrase detected in {{tool_name}} parameters: {{credential_types}}.",
};
