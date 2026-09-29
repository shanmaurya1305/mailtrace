/**
 * MAILTRACE 2.0 - Background Service Worker
 * Handles lifecycle events and optional background task orchestration.
 */

chrome.runtime.onInstalled.addListener((details) => {
  console.log('[MAILTRACE] Extension installed/updated:', details.reason);
});

// Listener for background messaging if delegated from popup or content script
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'PING') {
    sendResponse({ status: 'ok', service: 'mailtrace-background' });
    return true;
  }
});
