// Copyright (c) 2026 Omnodex, LLC. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of Omnodex, licensed under the GNU Affero General
// Public License v3.0. You may obtain a copy at https://omnodex.com/licensing
// A commercial license is available for use without copyleft obligations.
/**
 * @omnodex/mcp-proxy
 *
 * Public API surface. The MCPProxy class is the primary export; everything
 * else is exported for testing and for the CLI integration layer.
 */

export { MCPProxy } from "./mcp-proxy.js";
export { UpstreamClientPool, McpToolNotFoundError } from "./upstream-client.js";
export type { PrefixedTool, UpstreamCallResult } from "./upstream-client.js";
export { callToolWithEvents } from "./event-emitter.js";
export type { CallToolOptions, CallToolOutcome } from "./event-emitter.js";
export { runProxyServer } from "./proxy-server.js";
export type { ProxyServerOptions } from "./proxy-server.js";
export {
  ProxyConfigSchema,
  loadProxyConfig,
  resolveUpstreamEnv,
  shouldRedactParams,
  toolNamePrefix,
} from "./config.js";
export type {
  ProxyConfig,
  UpstreamServer,
  StdioUpstream,
  HttpUpstream,
} from "./config.js";
