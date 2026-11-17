import React, { useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { guideSetup, GuideLanguage, snippets } from '../data/connectGuideSnippets';

interface GuideApp {
  id: string;
  name: string;
  environment: 'dev' | 'prod';
  total_requests: number;
}

interface ConnectionTest {
  appId: string;
  status: 'testing' | 'connected' | 'not_connected';
  message?: string;
}

interface ConnectGuideViewProps {
  apps: GuideApp[];
  platformUrl: string;
  guideApiKeyPlaceholder: string;
  guideApiKey: string;
  guideSelectedAppId: string;
  setGuideSelectedAppId: (id: string) => void;
  guideApiKeys: Record<string, string>;
  connectionTestKey: string;
  setConnectionTestKey: (value: string) => void;
  connectionTest: ConnectionTest | null;
  handleTestConnection: () => void;
  guideLanguage: GuideLanguage;
  setGuideLanguage: (language: GuideLanguage) => void;
}

export function ConnectGuideView({
  apps, platformUrl, guideApiKeyPlaceholder, guideApiKey, guideSelectedAppId,
  setGuideSelectedAppId, guideApiKeys, connectionTestKey, setConnectionTestKey,
  connectionTest, handleTestConnection, guideLanguage, setGuideLanguage,
}: ConnectGuideViewProps) {
  const [isCodeCopied, setIsCodeCopied] = useState(false);
  const [isEnvCopied, setIsEnvCopied] = useState(false);
  const [isFullGuideCopied, setIsFullGuideCopied] = useState(false);
  const guideApp = apps.find((a) => a.id === guideSelectedAppId) || apps[0];
  const setup = guideSetup[guideLanguage];
  const currentGuideSetup = {
    ...setup,
    env: setup.env
      .replaceAll('{{platformUrl}}', platformUrl)
      .replaceAll('{{guideApiKeyPlaceholder}}', guideApiKeyPlaceholder),
  };
  const copyAllGuideContent = [
    `Connect ${guideApp?.name || 'this app'} to the API Security Gatekeeper`,
    '',
    'Steps:',
    '1. Copy your API key below.',
    '2. Open your app\'s project folder.',
    `3. Create or open ${currentGuideSetup.file}.`,
    '4. Paste the code and your key.',
    '5. Restart your app and click "Test connection" here.',
    '',
    `File: ${currentGuideSetup.file}`,
    `Install: ${currentGuideSetup.install}`,
    `Main server file: ${currentGuideSetup.main}`,
    '.env:',
    currentGuideSetup.env,
    currentGuideSetup.note,
    '',
    snippets[guideLanguage],
  ].join('\n');
  const copyContent = (content: string, setCopied: (value: boolean) => void) => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (

          <div className="flex flex-col gap-6">
            <div>
              <h2 className="text-lg font-bold text-slate-900 tracking-tight">Connect Any Backend (Integration Guide)</h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Follow the steps for one registered app and one language at a time. The reporter sends request metadata in the background.
              </p>
            </div>

            {/* Application selector and setup steps */}
            <div className="bg-white border border-slate-200 rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold text-slate-700">App:</span>
                <select
                  value={guideSelectedAppId}
                  onChange={(e) => setGuideSelectedAppId(e.target.value)}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-50 border border-slate-300 rounded-lg text-slate-800 focus:border-blue-600 focus:outline-none cursor-pointer"
                >
                  {apps.length === 0 && <option value="">No registered apps</option>}
                  {apps.map((app) => (
                    <option key={app.id} value={app.id}>
                      {app.name} ({app.environment})
                    </option>
                  ))}
                </select>
              </div>

              {guideApp && (
                <div className="flex items-center gap-2">
                  {!guideApiKeys[guideApp.id] && (
                    <input
                      type="password"
                      value={connectionTestKey}
                      onChange={(e) => setConnectionTestKey(e.target.value)}
                      placeholder="Paste key for this test only"
                      className="w-48 px-2.5 py-1.5 text-xs border border-slate-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  )}
                  <button
                    type="button"
                    onClick={() => void handleTestConnection()}
                    disabled={connectionTest?.status === 'testing'}
                    className="px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 cursor-pointer"
                  >
                    {connectionTest?.appId === guideApp.id && connectionTest.status === 'testing' ? 'Testing...' : 'Test connection'}
                  </button>
                </div>
              )}
            </div>

            {!guideApp ? (
              <div className="bg-white border border-slate-200 rounded-lg p-10 text-center text-sm text-slate-600">
                Register an application first to get a real API key and connection instructions.
              </div>
            ) : (
            <>
            {guideApp.total_requests === 0 && (
              <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-xs text-amber-900 font-medium">
                This app hasn't sent any traffic yet. Follow the steps below to connect it.
              </div>
            )}

            {connectionTest?.appId === guideApp.id && connectionTest.status === 'connected' && (
              <div className="bg-emerald-50 border border-emerald-200 rounded-lg px-4 py-3 text-xs text-emerald-800 font-semibold">
                {connectionTest.message}
              </div>
            )}
            {connectionTest?.appId === guideApp.id && connectionTest.status === 'not_connected' && (
              <div className="bg-rose-50 border border-rose-200 rounded-lg px-4 py-3 text-xs text-rose-800">
                <p className="font-semibold">{connectionTest.message}</p>
                <ul className="list-disc ml-5 mt-1 space-y-0.5">
                  <li>Is MONITOR_URL correct?</li>
                  <li>Did you restart your app after adding the .env values?</li>
                  <li>Is the key copied in full?</li>
                </ul>
              </div>
            )}

            <div className="bg-white border border-slate-200 rounded-lg p-5">
              <h3 className="text-sm font-bold text-slate-900 mb-3">Setup steps</h3>
              <ol className="grid gap-2 text-xs text-slate-700">
                <li><strong>Step 1:</strong> Copy your API key below.</li>
                <li><strong>Step 2:</strong> Open your app's project folder.</li>
                <li><strong>Step 3:</strong> Create or open the file shown below for your language.</li>
                <li><strong>Step 4:</strong> Paste the code and your key.</li>
                <li><strong>Step 5:</strong> Restart your app and click "Test connection" here.</li>
              </ol>
              <div className="mt-4 p-3 bg-slate-50 border border-slate-200 rounded-lg">
                <div className="text-xs font-bold text-slate-700 mb-1">Your API key</div>
                <code className="text-xs font-mono text-blue-700 break-all">
                  {guideApiKey || 'Key unavailable in this browser — regenerate this app key to display it again.'}
                </code>
                <p className="text-xs text-slate-500 mt-2">
                  For your safety, we only store a scrambled version of your key. We can never show it to you again after you close this box — if you lose it, regenerate instead.
                </p>
              </div>
            </div>

            {/* Language Tabs & Instructions */}
            <div className="bg-white border border-slate-200 rounded-md overflow-hidden flex flex-col">
              <div className="px-5 py-3 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
                {/* Language Switcher */}
                <div className="flex items-center gap-1.5">
                  {[
                    { id: 'node', label: 'Node.js / Express' },
                    { id: 'python', label: 'Python (FastAPI / Flask)' },
                    { id: 'java', label: 'Java (Spring Boot Filter)' },
                    { id: 'php', label: 'PHP' },
                  ].map((lang) => (
                    <button
                      key={lang.id}
                      onClick={() => setGuideLanguage(lang.id as any)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                        guideLanguage === lang.id
                          ? 'bg-blue-600 text-white'
                          : 'bg-white text-slate-600 hover:text-slate-900 border border-slate-200'
                      }`}
                    >
                      {lang.label}
                    </button>
                  ))}
                </div>

                {/* Copy Snippet Button */}
                <div className="flex flex-col items-end gap-1">
                  <button
                    onClick={() => copyContent(copyAllGuideContent, setIsFullGuideCopied)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg cursor-pointer transition-colors"
                  >
                    {isFullGuideCopied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{isFullGuideCopied ? 'Copied!' : 'Copy full guide'}</span>
                  </button>
                  <span className="text-xs text-slate-500">For sharing in chat or a README — not for pasting into your code file.</span>
                </div>
              </div>

              <div className="p-5 grid gap-4 text-xs">
                <div>
                  <div className="font-bold text-slate-800 mb-1">Create this file</div>
                  <code className="font-mono text-blue-700">{currentGuideSetup.file}</code>
                </div>
                <div>
                  <div className="font-bold text-slate-800 mb-1">Install what it needs</div>
                  <p className="text-slate-600">{currentGuideSetup.install}</p>
                </div>
                <div>
                  <div className="font-bold text-slate-800 mb-1">Turn it on in your main server file</div>
                  <p className="text-slate-600">{currentGuideSetup.main}</p>
                </div>
                <div>
                  <div className="flex items-center justify-between gap-3 mb-1">
                    <div className="font-bold text-slate-800">Set these values in .env</div>
                    <button
                      type="button"
                      onClick={() => copyContent(currentGuideSetup.env, setIsEnvCopied)}
                      className="flex items-center gap-1 px-2 py-1 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-md cursor-pointer"
                    >
                      {isEnvCopied ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>{isEnvCopied ? 'Copied!' : 'Copy'}</span>
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-100 rounded-lg font-mono text-slate-800 overflow-x-auto">{currentGuideSetup.env}</pre>
                </div>
                <div className="p-3 bg-blue-50 border border-blue-100 rounded-lg text-blue-900">
                  {currentGuideSetup.note}
                </div>
                <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-amber-900">
                  <strong>Important:</strong> If your Node app runs on another computer, do not use <code className="font-mono">http://localhost:3000</code>. Set <code className="font-mono">MONITOR_URL</code> to this dashboard's reachable LAN or public URL, and allow inbound access to port 3000.
                </div>
              </div>

              {/* Code block */}
              <div className="p-4 bg-slate-950 overflow-x-auto">
                <div className="flex items-center justify-between gap-3 mb-3">
                  <span className="text-xs font-semibold text-slate-400">Source code</span>
                  <button
                    type="button"
                    onClick={() => copyContent(snippets[guideLanguage], setIsCodeCopied)}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md cursor-pointer"
                  >
                    {isCodeCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{isCodeCopied ? 'Copied!' : 'Copy code'}</span>
                  </button>
                </div>
                <pre className="text-xs font-mono text-slate-100 leading-relaxed">
                  {snippets[guideLanguage]}
                </pre>
              </div>
            </div>
            </>
            )}
          </div>
  );
}
