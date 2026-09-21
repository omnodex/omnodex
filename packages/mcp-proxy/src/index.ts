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
export type { MCPProxyOptions } from "./mcp-proxy.js";
export { createCloudPushQueue } from "./cloud-push.js";
export type {
  CloudPushQueue,
  CloudPushQueueOptions,
  CloudPushFn,
} from "./cloud-push.js";
export { startAutoSyncTimer } from "./background-sync.js";
export type {
  AutoSyncTimer,
  AutoSyncTimerOptions,
  StartSyncFn,
} from "./background-sync.js";
export {
  UpstreamClientPool,
  McpToolNotFoundError,
  McpUpstreamUnavailableError,
  describeUnavailable,
} from "./upstream-client.js";
export type {
  PrefixedTool,
  UpstreamCallResult,
  UpstreamState,
  UpstreamStatus,
} from "./upstream-client.js";
export { callToolWithEvents } from "./event-emitter.js";
export type { CallToolOptions, CallToolOutcome } from "./event-emitter.js";
export { runProxyServer } from "./proxy-server.js";
export {
  startProxyHttpServer,
  parseHttpListen,
  isLoopbackHost,
  HTTP_MCP_PATH,
} from "./http-server.js";
export type { HttpServeOptions, ProxyHttpServer, ProxyHttpServerOptions } from "./http-server.js";
export {
  TOOL_NAME_SEPARATOR,
  normalizeSchemaDialect,
  prefixedToolName,
  prefixToolDefinition,
  resolvePrefixedName,
} from "./core/tool-routing.js";
export {
  REDACTED_SENTINEL,
  redactParameters,
  buildSessionStartedEvent,
  buildSessionEndedEvent,
  buildToolInvokedEvent,
  buildToolCompletedEvent,
} from "./core/events.js";
export type { ProxyServerOptions } from "./proxy-server.js";
export { handleConnect, checkConnectionStatus } from "./connect-tool.js";
export type { ConnectionStatus } from "./connect-tool.js";
export {
  ProxyConfigSchema,
  loadProxyConfig,
  resolveUpstreamEnv,
  shouldRedactParams,
  toolNamePrefix,
  resolveHttpHeaders,
  redactSecrets,
} from "./config.js";
export type {
  ProxyConfig,
  UpstreamServer,
  StdioUpstream,
  HttpUpstream,
  UpstreamConnectionSettings,
} from "./config.js";
