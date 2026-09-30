// SPDX-FileCopyrightText: 2026 Omnodex
// SPDX-License-Identifier: AGPL-3.0-or-later
// Licensed under the GNU Affero General Public License v3.0
// See https://omnodex.com/licensing for commercial license options
// Commercial licensing available for organizations that cannot use AGPL

import { createRoot } from "react-dom/client";
import { App } from "./App.js";
import "./styles.css";

createRoot(document.getElementById("root")!).render(<App />);
