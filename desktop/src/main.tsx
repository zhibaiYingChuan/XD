/* SPDX-License-Identifier: DaoTi-Research-1.0
   Copyright (c) 2026 独立研究者，知白

   React 挂载点。
*/

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { initAdminToken } from './services/api';
import './styles.css';

// ★ P0-5：桌面端把管理令牌交给前端，供「浏览器回退通道」带上
//   X-Admin-Token。纯浏览器预览拿不到令牌，该调用直接空转。
void initAdminToken();

const root = document.getElementById('root');
if (!root) {
  throw new Error('找不到 #root 挂载点');
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
