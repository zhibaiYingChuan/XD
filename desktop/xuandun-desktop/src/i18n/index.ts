const zh = {
  app: {
    title: '道体·玄盾',
    subtitle: '桌面安全守护',
  },
  nav: {
    dashboard: '仪表盘',
    detect: '检测',
    agents: 'Agent',
    logs: '日志',
    settings: '设置',
  },
  dashboard: {
    engineStatus: '引擎状态',
    online: '在线运行',
    offline: '离线',
    currentMode: '当前模式',
    uptime: '运行时间',
    totalRequests: '总请求数',
    totalBlocked: '拦截次数',
    blockRate: '拦截率',
    requestTrend: '请求趋势',
    trustDistribution: '信任等级分布',
    recentBlocks: '最近拦截记录',
    collecting: '数据采集中，请稍候...',
    noBlocks: '暂无拦截记录',
    engineError: '无法连接到引擎',
    engineWarning: '引擎运行异常，部分功能可能受限',
  },
  agents: {
    title: 'Agent 发现',
    running: '个运行中',
    runningStatus: '运行中',
    stopped: '已停止',
    noAgents: '未发现任何 Agent',
    discoverError: '无法发现 Agent',
    policy: '防护策略',
    refresh: '刷新',
    refreshing: '刷新中...',
  },
  logs: {
    title: '日志查看',
    all: '全部',
    blocked: '拦截',
    allowed: '放行',
    allStages: '全部阶段',
    searchPlaceholder: '搜索文本/会话ID...',
    loading: '加载中...',
    noLogs: '暂无日志记录',
    time: '时间',
    textPreview: '文本摘要',
    result: '结果',
    trustLevel: '信任等级',
    rejectStage: '拦截阶段',
    session: '会话',
    prev: '上一页',
    next: '下一页',
  },
  settings: {
    protectionMode: '防护模式',
    highSecurity: '高安全',
    highSecurityDesc: '最严格的防护策略，可能产生较多误报',
    balanced: '平衡',
    balancedDesc: '兼顾安全与可用性的推荐策略',
    lowFalsePositive: '低误报',
    lowFalsePositiveDesc: '减少误报，适合对可用性要求高的场景',
    generalSettings: '通用设置',
    autoStart: '开机自启动',
    autoStartDesc: '系统启动时自动运行玄盾',
    trafficIntercept: '流量拦截',
    trafficInterceptDesc: '启用实时流量拦截功能',
    domainAdaptive: '领域自适应',
    safeWarmup: '良性预热文本',
    safeWarmupPlaceholder: '输入领域相关的良性文本，每行一条...',
    attackWarmup: '攻击预热文本',
    attackWarmupPlaceholder: '输入已知的攻击样本，每行一条...',
    submitWarmup: '提交预热',
    securityAudit: '安全与审计',
    auditIntegrity: '审计日志完整性',
    auditIntegrityDesc: '验证日志哈希链是否完整未被篡改',
    verify: '验证',
    keyProtection: '密钥保护',
    keyProtectionDesc: '将引擎密钥存储到操作系统密钥库',
    generateKey: '生成密钥',
    deleteKey: '删除密钥',
    stored: '已存储',
    notSet: '未设置',
    engineManagement: '引擎管理',
    restartEngine: '重启引擎',
    stopEngine: '停止引擎',
    restarting: '重启中...',
    stopping: '停止中...',
    modeUpdated: '模式已更新',
    modeUpdateFailed: '模式更新失败',
    settingsSaved: '设置已保存',
    settingsSaveFailed: '设置保存失败',
  },
  wizard: {
    welcome: '欢迎使用道体·玄盾',
    welcomeDesc: '桌面端 AI Agent 安全守护系统',
    chooseMode: '选择防护模式',
    chooseModeDesc: '根据您的使用场景选择合适的防护模式',
    complete: '配置完成',
    completeDesc: '玄盾已就绪，开始守护您的 AI Agent',
    start: '开始使用',
  },
};

const en: typeof zh = {
  app: { title: 'Daoti XuanDun', subtitle: 'Desktop Security Guard' },
  nav: { dashboard: 'Dashboard', detect: 'Detect', agents: 'Agents', logs: 'Logs', settings: 'Settings' },
  dashboard: {
    engineStatus: 'Engine Status', online: 'Online', offline: 'Offline',
    currentMode: 'Current Mode', uptime: 'Uptime',
    totalRequests: 'Total Requests', totalBlocked: 'Blocked', blockRate: 'Block Rate',
    requestTrend: 'Request Trend', trustDistribution: 'Trust Level Distribution',
    recentBlocks: 'Recent Blocks', collecting: 'Collecting data...',
    noBlocks: 'No blocks yet', engineError: 'Cannot connect to engine',
    engineWarning: 'Engine running abnormally, some features may be limited',
  },
  agents: {
    title: 'Agent Discovery', running: 'running', runningStatus: 'Running', stopped: 'Stopped',
    noAgents: 'No agents found', discoverError: 'Cannot discover agents',
    policy: 'Policy', refresh: 'Refresh', refreshing: 'Refreshing...',
  },
  logs: {
    title: 'Log Viewer', all: 'All', blocked: 'Blocked', allowed: 'Allowed',
    allStages: 'All Stages', searchPlaceholder: 'Search text/session ID...',
    loading: 'Loading...', noLogs: 'No logs yet',
    time: 'Time', textPreview: 'Text Preview', result: 'Result',
    trustLevel: 'Trust Level', rejectStage: 'Reject Stage', session: 'Session',
    prev: 'Previous', next: 'Next',
  },
  settings: {
    protectionMode: 'Protection Mode', highSecurity: 'High Security',
    highSecurityDesc: 'Strictest protection, may produce more false positives',
    balanced: 'Balanced', balancedDesc: 'Recommended balance of security and usability',
    lowFalsePositive: 'Low FP', lowFalsePositiveDesc: 'Fewer false positives, for high-availability scenarios',
    generalSettings: 'General Settings', autoStart: 'Auto Start',
    autoStartDesc: 'Run XuanDun on system startup', trafficIntercept: 'Traffic Intercept',
    trafficInterceptDesc: 'Enable real-time traffic interception',
    domainAdaptive: 'Domain Adaptive', safeWarmup: 'Safe Warmup Texts',
    safeWarmupPlaceholder: 'Enter domain-specific safe texts, one per line...',
    attackWarmup: 'Attack Warmup Texts',
    attackWarmupPlaceholder: 'Enter known attack samples, one per line...',
    submitWarmup: 'Submit Warmup', securityAudit: 'Security & Audit',
    auditIntegrity: 'Audit Log Integrity', auditIntegrityDesc: 'Verify hash chain integrity',
    verify: 'Verify', keyProtection: 'Key Protection',
    keyProtectionDesc: 'Store engine key in OS keychain',
    generateKey: 'Generate Key', deleteKey: 'Delete Key',
    stored: 'Stored', notSet: 'Not Set', engineManagement: 'Engine Management',
    restartEngine: 'Restart Engine', stopEngine: 'Stop Engine',
    restarting: 'Restarting...', stopping: 'Stopping...',
    modeUpdated: 'Mode updated', modeUpdateFailed: 'Mode update failed',
    settingsSaved: 'Settings saved', settingsSaveFailed: 'Settings save failed',
  },
  wizard: {
    welcome: 'Welcome to Daoti XuanDun', welcomeDesc: 'Desktop AI Agent Security Guard',
    chooseMode: 'Choose Protection Mode', chooseModeDesc: 'Select a protection mode for your scenario',
    complete: 'Setup Complete', completeDesc: 'XuanDun is ready to guard your AI Agents',
    start: 'Get Started',
  },
};

type Lang = 'zh' | 'en';
type TranslationKeys = typeof zh;

const translations: Record<Lang, TranslationKeys> = { zh, en };

let currentLang: Lang = 'zh';

export function setLanguage(lang: Lang) {
  currentLang = lang;
  localStorage.setItem('xuandun-lang', lang);
}

export function getLanguage(): Lang {
  const saved = localStorage.getItem('xuandun-lang');
  if (saved === 'en' || saved === 'zh') {
    currentLang = saved;
  }
  return currentLang;
}

export function t(path: string): string {
  const keys = path.split('.');
  let result: any = translations[currentLang];
  for (const key of keys) {
    if (result && typeof result === 'object' && key in result) {
      result = result[key];
    } else {
      return path;
    }
  }
  return typeof result === 'string' ? result : path;
}

export { type Lang, type TranslationKeys };
