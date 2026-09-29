import type { ExtractedEmailData, ExtensionMessage, EmailContentResultMessage } from './types';

/**
 * Extracts visible email metadata from Gmail's web client DOM.
 * Treats all email content as untrusted text without executing HTML or following links.
 */
export function extractGmailEmail(): { success: boolean; data?: ExtractedEmailData; error?: string } {
  try {
    // 1. Extract Subject
    // Gmail uses h2.hP for email subject in thread view
    const subjectEl = document.querySelector('h2.hP') ||
                      document.querySelector('h2[data-thread-perm-id]') ||
                      document.querySelector('div[role="main"] h2');
    let subject = subjectEl?.textContent?.trim() || '';
    if (!subject && document.title) {
      // Fallback: title often formatted as "Subject - user@domain - Gmail"
      const titleClean = document.title.replace(/- Gmail$/i, '').trim();
      if (titleClean && !titleClean.toLowerCase().includes('inbox')) {
        subject = titleClean;
      }
    }

    // 2. Extract Sender
    // In Gmail, sender element usually has class .gD and attribute 'email'
    const senderEl = document.querySelector('span.gD[email]') ||
                     document.querySelector('span.gD') ||
                     document.querySelector('span[email]');
    let sender = '';
    if (senderEl) {
      const emailAttr = senderEl.getAttribute('email');
      const name = senderEl.textContent?.trim() || '';
      if (emailAttr && name && name !== emailAttr) {
        sender = `${name} <${emailAttr}>`;
      } else if (emailAttr) {
        sender = emailAttr;
      } else {
        sender = name;
      }
    }

    // 3. Extract Recipient
    const recipientEl = document.querySelector('span.g2') ||
                        document.querySelector('.adn .mD span[email]');
    let recipient = recipientEl?.getAttribute('email') || recipientEl?.textContent?.trim() || '';

    // 4. Extract Visible Body Text
    // Gmail message bodies are enclosed in containers with classes .a3s.aiL or .a3s
    const bodyContainers = document.querySelectorAll('.a3s.aiL, .a3s');
    let bodyText = '';
    if (bodyContainers.length > 0) {
      // Pick the active / last expanded message body
      const activeBody = bodyContainers[bodyContainers.length - 1];
      // Use innerText to get clean visible rendered text without HTML tags
      bodyText = (activeBody as HTMLElement).innerText?.trim() || '';
    }

    // 5. Extract Visible Links/URLs safely (without navigating, clicking, or fetching)
    const urls: string[] = [];
    const seenUrls = new Set<string>();

    if (bodyContainers.length > 0) {
      const activeBody = bodyContainers[bodyContainers.length - 1];
      const linkElements = activeBody.querySelectorAll('a[href]');
      linkElements.forEach((el) => {
        let rawHref = el.getAttribute('href') || '';
        // Skip javascript:, mailto:, internal anchors, and internal gmail links
        if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:')) {
          return;
        }

        // Handle Google redirect wrappers: https://www.google.com/url?q=<target>&...
        if (rawHref.includes('google.com/url?') && rawHref.includes('q=')) {
          try {
            const urlObj = new URL(rawHref);
            const target = urlObj.searchParams.get('q');
            if (target) {
              rawHref = target;
            }
          } catch {
            // Ignore parsing error
          }
        }

        if (rawHref.startsWith('http://') || rawHref.startsWith('https://')) {
          if (!seenUrls.has(rawHref)) {
            seenUrls.add(rawHref);
            urls.push(rawHref);
          }
        }
      });
    }

    // Check if an email was actually found
    if (!subject && !bodyText && !sender) {
      return {
        success: false,
        error: 'No open Gmail email detected. Please click into an email thread to analyze.',
      };
    }

    return {
      success: true,
      data: {
        subject: subject || 'Untitled Email',
        sender: sender || 'Unknown Sender',
        recipient: recipient || 'Unknown Recipient',
        body: bodyText,
        urls,
        extractionTimestamp: new Date().toISOString(),
        sourceUrl: window.location.href,
      },
    };
  } catch (err: any) {
    return {
      success: false,
      error: `Failed to extract email DOM: ${err?.message || String(err)}`,
    };
  }
}

// Register message listener for popup communication
chrome.runtime.onMessage.addListener((message: ExtensionMessage, _sender, sendResponse) => {
  if (message.type === 'GET_EMAIL_CONTENT') {
    const result = extractGmailEmail();
    const response: EmailContentResultMessage = {
      type: 'EMAIL_CONTENT_RESULT',
      success: result.success,
      data: result.data,
      error: result.error,
    };
    sendResponse(response);
    return true; // Keep channel open for async response
  }
});
