import { useState, useEffect } from 'react';

interface OnboardingWizardProps {
  totalRequests: number;
  onSkip: () => void;
  onNavigate: (path: string) => void;
}

type MethodId = 'proxy' | 'sdk' | 'test';

interface Method {
  id: MethodId;
  icon: string;
  title: string;
  desc: string;
  steps: { title: string; detail: string }[];
}

const METHODS: Method[] = [
  {
    id: 'proxy',
    icon: '🔌',
    title: '配置 AI 工具代理',
    desc: '将玄盾设为 Claude Desktop / Cursor 等 AI 工具的安全代理，无需改动应用代码',
    steps: [
      { title: '启动代理服务', detail: '在「设置」页面或状态栏点击「启动代理」，玄盾将在 127.0.0.1:18765 监听' },
      { title: '配置 AI 工具代理', detail: '打开 Claude Desktop / Cursor 的网络设置，将 HTTP 代理地址设为 127.0.0.1:18765' },
      { title: '或使用 MCP Server 模式', detail: '在 Claude Desktop 配置文件中添加 xuandun_protect 工具，实现更精细的拦截控制' },
      { title: '发送测试请求', detail: '在 AI 工具中发送一条消息，回到玄盾 Dashboard 确认流量已被检测到' },
    ],
  },
  {
    id: 'sdk',
    icon: '📦',
    title: 'SDK 集成到你的服务',
    desc: '使用 Python SDK 将玄盾集成到 FastAPI / Flask 等后端应用',
    steps: [
      { title: '安装 SDK', detail: '执行 pip install daoti-xuandun==1.1.0 安装最新版 SDK' },
      { title: '引入并初始化', detail: 'from daoti_xuandun import XuanDun; shield = XuanDun()  # 默认启用观察模式' },
      { title: '调用检测接口', detail: 'result = shield.protect("用户输入"); if not result.allowed: 拦截' },
      { title: '查看拦截日志', detail: '拦截记录会写入玄盾 Dashboard 的日志页面，可在「日志」中查看详情' },
    ],
  },
  {
    id: 'test',
    icon: '🧪',
    title: '运行模拟测试',
    desc: '使用内置 200+ 攻击样本验证防护效果，无需真实接入即可体验',
    steps: [
      { title: '打开模拟测试页面', detail: '在左侧导航栏点击「模拟测试」进入测试页面' },
      { title: '选择测试模式', detail: '推荐选择「快速验证」模式，覆盖 6 大类攻击样本' },
      { title: '运行测试', detail: '点击「运行测试」按钮，约 15 秒内完成 200+ 样本检测' },
      { title: '查看报告', detail: '测试完成后查看拦截率、误报率、分类统计，确认防护效果后正式接入' },
    ],
  },
];

const WIZARD_STEPS = ['选择接入方式', '按步骤配置', '验证连通性', '完成'];

export default function OnboardingWizard({ totalRequests, onSkip, onNavigate }: OnboardingWizardProps) {
  const [wizardStep, setWizardStep] = useState(0);
  const [selectedMethod, setSelectedMethod] = useState<MethodId | null>(null);
  const [checkedSteps, setCheckedSteps] = useState<Record<number, boolean>>({});
  const [waitingForTraffic, setWaitingForTraffic] = useState(false);

  useEffect(() => {
    if (wizardStep === 2 && waitingForTraffic && totalRequests > 0) {
      setWaitingForTraffic(false);
      setWizardStep(3);
    }
  }, [wizardStep, waitingForTraffic, totalRequests]);

  const method = METHODS.find((m) => m.id === selectedMethod);

  const handleSelectMethod = (id: MethodId) => {
    setSelectedMethod(id);
    setCheckedSteps({});
    setWizardStep(1);
  };

  const handleToggleStep = (idx: number) => {
    setCheckedSteps((prev) => ({ ...prev, [idx]: !prev[idx] }));
  };

  const allStepsChecked = method ? method.steps.every((_, idx) => checkedSteps[idx]) : false;

  const handleNext = () => {
    if (wizardStep === 1 && selectedMethod === 'test') {
      onNavigate('/simulation');
      onSkip();
      return;
    }
    if (wizardStep === 1) {
      setWaitingForTraffic(true);
    }
    setWizardStep((prev) => Math.min(prev + 1, 3));
  };

  const handlePrev = () => {
    setWizardStep((prev) => Math.max(prev - 1, 0));
    if (wizardStep === 1) {
      setSelectedMethod(null);
      setCheckedSteps({});
    }
  };

  const handleVerifyNow = () => {
    if (totalRequests > 0) {
      setWizardStep(3);
    }
  };

  const progress = ((wizardStep + 1) / WIZARD_STEPS.length) * 100;

  return (
    <div className="onboarding-wizard-overlay">
      <div className="onboarding-wizard">
        <div className="wizard-header">
          <div className="wizard-title-row">
            <span className="wizard-icon">🚀</span>
            <h2 className="wizard-title">让玄盾开始工作</h2>
            <button className="wizard-skip-btn" onClick={onSkip} title="跳过向导">
              稍后再说
            </button>
          </div>
          <div className="wizard-progress-bar">
            <div className="wizard-progress-fill" style={{ width: `${progress}%` }}></div>
          </div>
          <div className="wizard-steps-indicator">
            {WIZARD_STEPS.map((label, idx) => (
              <div
                key={idx}
                className={`wizard-step-dot ${idx === wizardStep ? 'active' : ''} ${idx < wizardStep ? 'done' : ''}`}
              >
                <span className="wizard-step-num">{idx < wizardStep ? '✓' : idx + 1}</span>
                <span className="wizard-step-label">{label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="wizard-body">
          {wizardStep === 0 && (
            <div className="wizard-step-content">
              <p className="wizard-intro">
                玄盾已就绪，但尚未检测到任何流量。请选择一种接入方式，我们将引导您完成配置。
              </p>
              <div className="wizard-method-grid">
                {METHODS.map((m) => (
                  <div
                    key={m.id}
                    className={`wizard-method-card ${selectedMethod === m.id ? 'selected' : ''}`}
                    onClick={() => handleSelectMethod(m.id)}
                  >
                    <div className="wizard-method-icon">{m.icon}</div>
                    <div className="wizard-method-title">{m.title}</div>
                    <div className="wizard-method-desc">{m.desc}</div>
                    <div className="wizard-method-hint">
                      {m.steps.length} 步 · 约 {m.id === 'test' ? '1' : '5'} 分钟
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {wizardStep === 1 && method && (
            <div className="wizard-step-content">
              <div className="wizard-method-header">
                <span className="wizard-method-icon-lg">{method.icon}</span>
                <div>
                  <div className="wizard-method-title-lg">{method.title}</div>
                  <div className="wizard-method-desc-lg">{method.desc}</div>
                </div>
              </div>
              <div className="wizard-checklist">
                {method.steps.map((step, idx) => (
                  <div
                    key={idx}
                    className={`wizard-checklist-item ${checkedSteps[idx] ? 'checked' : ''}`}
                    onClick={() => handleToggleStep(idx)}
                  >
                    <div className={`wizard-checkbox ${checkedSteps[idx] ? 'checked' : ''}`}>
                      {checkedSteps[idx] ? '✓' : ''}
                    </div>
                    <div className="wizard-checklist-text">
                      <div className="wizard-checklist-title">
                        <span className="wizard-step-index">步骤 {idx + 1}</span>
                        {step.title}
                      </div>
                      <div className="wizard-checklist-detail">{step.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
              {!allStepsChecked && (
                <div className="wizard-hint-bar">
                  💡 勾选所有步骤后可进入下一步验证连通性
                </div>
              )}
            </div>
          )}

          {wizardStep === 2 && (
            <div className="wizard-step-content">
              <div className="wizard-verify-section">
                {totalRequests > 0 ? (
                  <div className="wizard-verify-success">
                    <div className="wizard-verify-icon">✅</div>
                    <h3>已检测到流量接入！</h3>
                    <p>玄盾已成功检测到 {totalRequests} 条请求，接入配置正确。</p>
                  </div>
                ) : (
                  <div className="wizard-verify-waiting">
                    <div className="wizard-verify-icon spinning">🔄</div>
                    <h3>正在等待流量接入...</h3>
                    <p>
                      请按照上一步的指引在 AI 工具中发送消息，或使用 SDK 发送请求。
                      玄盾检测到流量后将自动进入下一步。
                    </p>
                    {method?.id === 'proxy' && (
                      <div className="wizard-verify-tip">
                        提示：确认代理已启动（设置页面 → 启动代理），且 AI 工具代理地址指向 127.0.0.1:18765
                      </div>
                    )}
                    {method?.id === 'sdk' && (
                      <div className="wizard-verify-tip">
                        提示：确保 SDK 已正确安装并调用 shield.protect()，检查控制台是否有错误输出
                      </div>
                    )}
                    <button className="btn btn-sm btn-secondary" onClick={handleVerifyNow}>
                      手动检查
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {wizardStep === 3 && (
            <div className="wizard-step-content">
              <div className="wizard-complete">
                <div className="wizard-complete-icon">🎉</div>
                <h2>接入完成！</h2>
                <p>
                  玄盾已开始保护您的 AI 应用。您可以在 Dashboard 查看实时拦截数据，
                  在「日志」页面查看详细记录，在「设置」调整防护策略。
                </p>
                <div className="wizard-complete-tips">
                  <div className="wizard-tip-item">
                    <span className="wizard-tip-icon">📊</span>
                    <span>Dashboard 提供趋势图、攻击分布和实时监控</span>
                  </div>
                  <div className="wizard-tip-item">
                    <span className="wizard-tip-icon">🔔</span>
                    <span>在「设置 → 告警通道」配置钉钉/飞书/邮件告警</span>
                  </div>
                  <div className="wizard-tip-item">
                    <span className="wizard-tip-icon">📄</span>
                    <span>在「安全报告」生成周报/月报复盘安全态势</span>
                  </div>
                </div>
                <button className="btn btn-primary wizard-complete-btn" onClick={onSkip}>
                  开始使用玄盾
                </button>
              </div>
            </div>
          )}
        </div>

        {wizardStep > 0 && wizardStep < 3 && (
          <div className="wizard-footer">
            <button className="btn btn-secondary btn-sm" onClick={handlePrev}>
              上一步
            </button>
            {wizardStep === 1 && (
              <button
                className="btn btn-primary btn-sm"
                onClick={handleNext}
                disabled={!allStepsChecked}
              >
                {selectedMethod === 'test' ? '前往测试页面' : '下一步：验证连通性'}
              </button>
            )}
            {wizardStep === 2 && totalRequests > 0 && (
              <button className="btn btn-primary btn-sm" onClick={() => setWizardStep(3)}>
                下一步：完成
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
