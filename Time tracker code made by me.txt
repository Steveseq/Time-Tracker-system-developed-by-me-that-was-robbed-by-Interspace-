// ==== CONFIG ==== Developer, Author and Owner of this code: Steve Sequeira.
const SHEET_NAME         = 'Sheet1'; // Change to your sheet name
const DAILY_HOURS        = 8;        // Standard working hours per day
const WORK_DAYS_IN_MONTH = 22;
const MONTHLY_HOURS      = DAILY_HOURS * WORK_DAYS_IN_MONTH;
const LOCK_KEY           = '__SCRIPT_LOCK__';
const ADMIN_EMAIL        = 'accounts.helpdesk@interspaceindia.co.in'; // **CHANGE THIS TO THE ACTUAL ADMIN EMAIL**

// Enhanced security and monitoring configuration
const SECURITY_CONFIG = {
  MAX_DAILY_ENTRIES: 20,        // Maximum entries per user per day
  MAX_HOURS_PER_ENTRY: 12,      // Maximum hours for a single entry
  SUSPICIOUS_EDIT_THRESHOLD: 5,  // Number of blocked edits before escalation
  MONITOR_COLUMNS: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], // All columns to monitor
  ALERT_COOLDOWN_MINUTES: 5    // Minimum time between alerts for same user (only for SUSPICIOUS_ACTIVITY alerts)
};

// Enhanced email templates
const EMAIL_TEMPLATES = {
  DATA_TAMPERING: {
    subject: 'SECURITY ALERT: Data Tampering Detected in Time Tracker',
    getBody: (userEmail, userName, sheetName, rangeAddress, attemptedValue, timestamp) => `
Dear Admin,

SECURITY ALERT: Unauthorized data manipulation attempt detected.

INCIDENT DETAILS:
- Employee: ${userName} (${userEmail})
- Spreadsheet: ${sheetName}
- Cell: ${rangeAddress}
- Attempted Value: ${attemptedValue}
- Timestamp: ${timestamp}
- Action Taken: Edit blocked and reverted
- Initiated By: ${userName}

This incident has been logged and the user has been notified that manual edits are not permitted.

Please review user access permissions if this behavior continues.

Regards,
Time Tracker Security System
    `
  },
  SUSPICIOUS_ACTIVITY: {
    subject: 'SECURITY ALERT: Suspicious Activity Pattern Detected',
    getBody: (userEmail, userName, activityType, details, timestamp) => `
Dear Admin,

SECURITY ALERT: Suspicious activity pattern detected.

INCIDENT DETAILS:
- Employee: ${userName} (${userEmail})
- Activity Type: ${activityType}
- Details: ${details}
- Timestamp: ${timestamp}
- Initiated By: ${userName}

RECOMMENDED ACTIONS:
1. Review user's recent activity
2. Verify user account security
3. Consider temporary access restriction if needed

This is an automated alert from the Time Tracker Security System.

Regards,
Time Tracker Security System
    `
  },
  TIMER_START: {
    subject: 'Time Tracker Alert: Timer Started',
    getBody: (userEmail, userName, client, department, timestamp) => `
Dear Admin,

TIMER START NOTIFICATION:

DETAILS:
- Employee: ${userName} (${userEmail})
- Client: ${client}
- Department: ${department}
- Timestamp: ${timestamp}
- Action: Timer Started
- Initiated By: ${userName}

This is an automated notification from the Time Tracker System.

Regards,
Time Tracker Security System
    `
  },
  TIMER_STOP: {
    subject: 'Time Tracker Alert: Timer Stopped',
    getBody: (userEmail, userName, hours, timestamp) => `
Dear Admin,

TIMER STOP NOTIFICATION:

DETAILS:
- Employee: ${userName} (${userEmail})
- Hours Logged: ${hours}
- Timestamp: ${timestamp}
- Action: Timer Stopped
- Initiated By: ${userName}

This is an automated notification from the Time Tracker System.

Regards,
Time Tracker Security System
    `
  }
};

// ENHANCED onEdit function with better detection and debugging
function onEdit(e) {
  try {
    // Log that the trigger fired for debugging
    console.log('onEdit trigger fired');
    
    const props = PropertiesService.getScriptProperties();
    
    // Check if script is locked (but don't return immediately - log first)
    const isLocked = props.getProperty(LOCK_KEY) === '1';
    if (isLocked) {
      console.log('Script is locked, skipping onEdit processing');
      return;
    }

    // Validate event object
    if (!e || !e.range) {
      console.log('Invalid event object or range');
      return;
    }

    const col = e.range.getColumn();
    const row = e.range.getRow();
    const userEmail = Session.getActiveUser().getEmail() || 'unknown@email.com';
    const userName = EMAIL_MAP[userEmail] || userEmail || 'Unknown User';
    const sheetName = e.source.getSheetName() || 'Unknown Sheet';
    const rangeAddress = e.range.getA1Notation();
    const attemptedValue = (e.value !== undefined && e.value !== null) ? e.value.toString() : 'Empty/Deleted';
    const timestamp = new Date().toLocaleString();

    // Log edit attempt details for debugging
    console.log(`Edit attempt: User=${userName}, Sheet=${sheetName}, Cell=${rangeAddress}, Value=${attemptedValue}, Row=${row}, Col=${col}`);

    // Check if this is the correct sheet (if SHEET_NAME is specified)
    if (SHEET_NAME && sheetName !== SHEET_NAME) {
      console.log(`Edit on different sheet (${sheetName}), ignoring`);
      return;
    }

    // Check if edit is in monitored columns and not header row
    if (SECURITY_CONFIG.MONITOR_COLUMNS.includes(col) && row > 1) {
      console.log('BLOCKING EDIT - Manual edit detected in monitored column');
      
      // Block the edit immediately
      try {
        e.range.setValue('EDIT BLOCKED - Contact Admin');
        console.log('Edit blocked successfully');
      } catch (blockError) {
        console.error('Failed to block edit:', blockError);
      }
      
      // Log the tampering attempt
      logSecurityIncident('DATA_TAMPERING', {
        userEmail: userEmail,
        userName: userName,
        sheetName: sheetName,
        rangeAddress: rangeAddress,
        attemptedValue: attemptedValue,
        timestamp: timestamp,
        row: row,
        column: col
      });

      // Send immediate admin alert - NO COOLDOWN FOR DATA_TAMPERING
      try {
        sendAdminAlert('DATA_TAMPERING', userEmail, userName, sheetName, rangeAddress, attemptedValue, timestamp);
        console.log('Admin alert sent successfully');
      } catch (alertError) {
        console.error('Failed to send admin alert:', alertError);
      }
      
      // Track repeated attempts
      trackSuspiciousActivity(userEmail, 'MANUAL_EDIT_ATTEMPT');
      
      // Show message to user
      try {
        SpreadsheetApp.getActiveSpreadsheet().toast(
          'Manual edits are not permitted.', 
          'Edit Blocked', 
          5
        );
        console.log('User notification shown');
      } catch (toastError) {
        console.error('Failed to show toast:', toastError);
      }
    } else {
      console.log(`Edit allowed: Column ${col} not monitored or header row (${row})`);
    }
    
  } catch (error) {
    console.error('onEdit function error:', error);
    // Log the error but don't let it break the system
    try {
      logSecurityIncident('ONEDIT_ERROR', {
        error: error.toString(),
        timestamp: new Date().toLocaleString(),
        userEmail: Session.getActiveUser().getEmail() || 'unknown'
      });
    } catch (logError) {
      console.error('Failed to log onEdit error:', logError);
    }
  }
}

// Function to manually install the onEdit trigger (for troubleshooting)
function installOnEditTrigger() {
  try {
    // Delete existing onEdit triggers first
    const triggers = ScriptApp.getProjectTriggers();
    triggers.forEach(trigger => {
      if (trigger.getHandlerFunction() === 'onEdit') {
        ScriptApp.deleteTrigger(trigger);
      }
    });
    
    // Install new onEdit trigger
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    ScriptApp.newTrigger('onEdit')
      .onEdit()
      .create();
    
    SpreadsheetApp.getActiveSpreadsheet().toast('onEdit trigger installed successfully', 'Trigger Setup', 3);
    console.log('onEdit trigger installed successfully');
    
  } catch (error) {
    console.error('Failed to install onEdit trigger:', error);
    SpreadsheetApp.getActiveSpreadsheet().toast('Failed to install trigger: ' + error.message, 'Error', 5);
  }
}

// Function to test the onEdit functionality manually
function testOnEditFunction() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_NAME) || ss.getActiveSheet();
    
    // Create a mock event object for testing
    const mockEvent = {
      range: sheet.getRange('C2'), // Test cell in monitored column
      value: 'TEST EDIT',
      source: ss
    };
    
    // Call onEdit with mock event
    onEdit(mockEvent);
    
    SpreadsheetApp.getActiveSpreadsheet().toast('onEdit test completed - check console logs', 'Test Complete', 3);
    
  } catch (error) {
    console.error('Test failed:', error);
    SpreadsheetApp.getActiveSpreadsheet().toast('Test failed: ' + error.message, 'Error', 5);
  }
}

// Enhanced suspicious activity tracking
function trackSuspiciousActivity(userEmail, activityType) {
  const props = PropertiesService.getScriptProperties();
  const key = `SUSPICIOUS_${userEmail}_${activityType}`;
  const currentCount = parseInt(props.getProperty(key) || '0');
  const newCount = currentCount + 1;
  
  props.setProperty(key, newCount.toString());
  
  // Set expiry for tracking (24 hours)
  const expiryKey = `${key}_EXPIRY`;
  const tomorrow = new Date();
  tomorrow.setDate(tomorrow.getDate() + 1);
  props.setProperty(expiryKey, tomorrow.getTime().toString());
  
  // Alert if threshold exceeded
  if (newCount >= SECURITY_CONFIG.SUSPICIOUS_EDIT_THRESHOLD) {
    const userName = EMAIL_MAP[userEmail] || userEmail || 'Unknown User';
    const details = `${newCount} blocked edit attempts in 24 hours (Threshold: ${SECURITY_CONFIG.SUSPICIOUS_EDIT_THRESHOLD})`;
    
    sendAdminAlert('SUSPICIOUS_ACTIVITY', userEmail, userName, activityType, details, new Date().toLocaleString());
    
    // Reset counter after alert
    props.deleteProperty(key);
    props.deleteProperty(expiryKey);
  }
}

// Enhanced admin alert system - FIXED TO SEND IMMEDIATE ALERTS FOR EDIT BLOCKING
function sendAdminAlert(alertType, ...args) {
  try {
    // Apply cooldown ONLY to SUSPICIOUS_ACTIVITY alerts, NOT to DATA_TAMPERING or timer alerts
    if (alertType === 'SUSPICIOUS_ACTIVITY') {
      if (!checkAlertCooldown(args[0], alertType)) {
        console.log(`Alert ${alertType} skipped due to cooldown`);
        return; // Skip if in cooldown period
      }
    }
    
    let subject, body;
    
    switch (alertType) {
      case 'DATA_TAMPERING':
        const [userEmail, userName, sheetName, rangeAddress, attemptedValue, timestamp] = args;
        subject = EMAIL_TEMPLATES.DATA_TAMPERING.subject;
        body = EMAIL_TEMPLATES.DATA_TAMPERING.getBody(userEmail, userName, sheetName, rangeAddress, attemptedValue, timestamp);
        break;
        
      case 'SUSPICIOUS_ACTIVITY':
        const [userEmail2, userName2, activityType, details, timestamp2] = args;
        subject = EMAIL_TEMPLATES.SUSPICIOUS_ACTIVITY.subject;
        body = EMAIL_TEMPLATES.SUSPICIOUS_ACTIVITY.getBody(userEmail2, userName2, activityType, details, timestamp2);
        break;
        
      case 'TIMER_START':
        const [userEmail3, userName3, client, department, timestamp3] = args;
        subject = EMAIL_TEMPLATES.TIMER_START.subject;
        body = EMAIL_TEMPLATES.TIMER_START.getBody(userEmail3, userName3, client, department, timestamp3);
        break;
        
      case 'TIMER_STOP':
        const [userEmail4, userName4, hours, timestamp4] = args;
        subject = EMAIL_TEMPLATES.TIMER_STOP.subject;
        body = EMAIL_TEMPLATES.TIMER_STOP.getBody(userEmail4, userName4, hours, timestamp4);
        break;
        
      default:
        console.log(`Unknown alert type: ${alertType}`);
        return;
    }
    
    // Send email to admin only (no user notification)
    MailApp.sendEmail({
      to: ADMIN_EMAIL,
      subject: subject,
      body: body,
      htmlBody: body.replace(/\n/g, '<br>')
    });
    
    // Log successful alert
    console.log(`Admin alert sent: ${alertType} at ${new Date().toLocaleString()}`);
    
  } catch (error) {
    console.error('Failed to send admin alert:', error);
    // Log the failure but don't notify user
    logSecurityIncident('EMAIL_FAILURE', {
      error: error.toString(),
      alertType: alertType,
      timestamp: new Date().toLocaleString()
    });
  }
}

// Alert cooldown management - Modified to use separate cooldowns for different alert types
function checkAlertCooldown(userEmail, alertType) {
  const props = PropertiesService.getScriptProperties();
  const cooldownKey = `ALERT_COOLDOWN_${userEmail}_${alertType}`;
  const lastAlert = props.getProperty(cooldownKey);
  
  if (lastAlert) {
    const lastAlertTime = new Date(parseInt(lastAlert));
    const now = new Date();
    const minutesSinceLastAlert = (now - lastAlertTime) / (1000 * 60);
    
    if (minutesSinceLastAlert < SECURITY_CONFIG.ALERT_COOLDOWN_MINUTES) {
      return false; // Still in cooldown
    }
  }
  
  // Set new cooldown
  props.setProperty(cooldownKey, new Date().getTime().toString());
  return true;
}

// Enhanced security incident logging
function logSecurityIncident(incidentType, details) {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    let logSheet;
    
    // Create security log sheet if it doesn't exist
    try {
      logSheet = ss.getSheetByName('Security_Log');
    } catch (e) {
      logSheet = ss.insertSheet('Security_Log');
      // Add headers
      logSheet.getRange(1, 1, 1, 8).setValues([[
        'Timestamp', 'Incident Type', 'User Email', 'User Name', 
        'Details', 'Sheet Name', 'Cell', 'Action Taken'
      ]]);
      logSheet.getRange(1, 1, 1, 8).setFontWeight('bold');
    }
    
    // Add log entry
    const row = logSheet.getLastRow() + 1;
    logSheet.getRange(row, 1, 1, 8).setValues([[
      new Date().toLocaleString(),
      incidentType,
      details.userEmail || 'System',
      details.userName || 'System',
      JSON.stringify(details),
      details.sheetName || SHEET_NAME,
      details.rangeAddress || 'N/A',
      'Admin Notified'
    ]]);
    
    // Auto-hide security log from regular users
    logSheet.hideSheet();
    
  } catch (error) {
    console.error('Failed to log security incident:', error);
  }
}

// Enhanced data validation for timer operations
function validateTimerData(userData) {
  const issues = [];
  const userEmail = Session.getActiveUser().getEmail();
  const today = new Date().toDateString();
  
  // Check daily entry limit
  const dailyEntries = getDailyEntriesCount(userEmail, today);
  if (dailyEntries >= SECURITY_CONFIG.MAX_DAILY_ENTRIES) {
    issues.push(`Exceeded daily entry limit (${SECURITY_CONFIG.MAX_DAILY_ENTRIES})`);
    sendAdminAlert('SUSPICIOUS_ACTIVITY', userEmail, userData.name, 'EXCESSIVE_ENTRIES', 
      `User attempted to create entry #${dailyEntries + 1} (Limit: ${SECURITY_CONFIG.MAX_DAILY_ENTRIES})`, 
      new Date().toLocaleString());
  }
  
  // Validate required fields
  if (!userData.client || userData.client.trim().length === 0) {
    issues.push('Client name is required');
  }
  
  if (!userData.department || !DEPARTMENTS.includes(userData.department)) {
    issues.push('Valid department is required');
  }
  
  if (!userData.briefedBy || !BRIEFED_BY_LIST.includes(userData.briefedBy)) {
    issues.push('Valid briefed by person is required');
  }
  
  return issues;
}

// Get daily entries count for a user
function getDailyEntriesCount(userEmail, dateString) {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(SHEET_NAME);
  const dataRange = sheet.getDataRange();
  const values = dataRange.getValues();
  
  let count = 0;
  for (let i = 1; i < values.length; i++) { // Skip header row
    const rowDate = values[i][COL.DATE - 1];
    const rowEmail = values[i][COL.NAME - 1];
    
    if (rowDate && rowEmail) {
      const entryDate = new Date(rowDate).toDateString();
      const entryUser = EMAIL_MAP[rowEmail] || rowEmail;
      const currentUser = EMAIL_MAP[userEmail] || userEmail;
      
      if (entryDate === dateString && entryUser === currentUser) {
        count++;
      }
    }
  }
  
  return count;
}

// Enhanced timer validation on stop
function validateTimerStop(startTime, stopTime, row) {
  const issues = [];
  const userEmail = Session.getActiveUser().getEmail();
  const userName = EMAIL_MAP[userEmail] || userEmail || 'Unknown User';
  
  if (!startTime || !stopTime) {
    issues.push('Invalid start or stop time');
    return issues;
  }
  
  const timeDiff = stopTime - startTime;
  const hours = timeDiff / (1000 * 60 * 60);
  
  // Check for unrealistic hours
  if (hours > SECURITY_CONFIG.MAX_HOURS_PER_ENTRY) {
    issues.push(`Entry duration exceeds maximum allowed (${SECURITY_CONFIG.MAX_HOURS_PER_ENTRY} hours)`);
    sendAdminAlert('SUSPICIOUS_ACTIVITY', userEmail, userName, 'EXCESSIVE_HOURS', 
      `Timer duration: ${hours.toFixed(2)} hours (Max: ${SECURITY_CONFIG.MAX_HOURS_PER_ENTRY})`, 
      new Date().toLocaleString());
  }
  
  // Check for negative time (clock manipulation)
  if (hours < 0) {
    issues.push('Invalid time sequence detected');
    sendAdminAlert('SUSPICIOUS_ACTIVITY', userEmail, userName, 'TIME_MANIPULATION', 
      `Negative time duration detected: ${hours.toFixed(2)} hours`, 
      new Date().toLocaleString());
  }
  
  return issues;
}

// NEW FUNCTION: Check if user has exceeded 12 hours and show popup
function checkAndWarnExceedingHours(hours, userName) {
  if (hours > SECURITY_CONFIG.MAX_HOURS_PER_ENTRY) {
    const ui = SpreadsheetApp.getUi();
    const response = ui.alert(
      '⚠️ EXCESSIVE HOURS WARNING ⚠️',
      `You have recorded ${hours.toFixed(2)} hours for this entry, which exceeds the maximum allowed ${SECURITY_CONFIG.MAX_HOURS_PER_ENTRY} hours.\n\n` +
      'Please ensure this is accurate. If this is correct, click "OK" to proceed.\n' +
      'If this is an error, click "CANCEL" to review your time entry.',
      ui.ButtonSet.OK_CANCEL
    );
    
    if (response === ui.Button.CANCEL) {
      return false; // User wants to cancel
    }
    
    // Log the warning
    logSecurityIncident('EXCESSIVE_HOURS_WARNING', {
      userEmail: Session.getActiveUser().getEmail(),
      userName: userName,
      hours: hours,
      maxAllowed: SECURITY_CONFIG.MAX_HOURS_PER_ENTRY,
      timestamp: new Date().toLocaleString()
    });
  }
  return true; // User confirmed or hours are within limit
}

// Lock utility (unchanged)
function setLock(val) {
  const props = PropertiesService.getScriptProperties();
  if (val) props.setProperty(LOCK_KEY, '1');
  else props.deleteProperty(LOCK_KEY);
}

// Predefined lists (unchanged)
const DEPARTMENTS = [
  'Elevate',
  'HyperGlocal',
  'Media Circle',
  "Interact X",
  'HR',
  'IT',
  'Finance/Accounts',
];

const BRIEFED_BY_LIST = [
  'Ajay Rathod',
  'Aref Khokher',
  'Arjan Biswas',
  'Ashish Wadhwa',
  'Bhanudas Kharmare',
  'Devendra Ghadge',
  'Devan Sharma',
  'Dhruvi Mandvia',
  'Ganesh Sagwekar',
  'Harmanpreet Singh',
  'Hasnain Haider',
  'Hoshang Katyayan',
  'Ishan Nair',
  'Ishika Malhotra',
  'Kaushik Chakravorty',
  'Kaamini Lotankar',
  'Khalid Ansari',
  'Nayan Kagathra',
  'Nikhil Rangnekar',
  'Pratik Shah',
  'Parag Mhatre',
  'Prakash Upadhyay',
  'Rajnikant Jha',
  'Sana Parulekar',
  'Satish Dubey',
  'Shailesh Agarwal',
  'Shailesh Joshi',
  'Shobhit Mathur',
  'Smita Kejriwal',
  'Srikanth Raman',
  'Stephen Gonsalves',
  'Sumit Taneja',
  'Steve Sequeira',
  'Suryakant Jadhav',
  'Rashmi Rao',
  'Umesh Gupta'
];

const TYPE_LIST = [
  'New',
  'Revision',
  'Pitch',
  'Existing'
];

// Map emails to display names - Updated with the 4 employees mentioned
const EMAIL_MAP = {
  'ganesh.sagwekar@interspaceindia.co.in': 'Ganesh',
  'nandini.hatkar@interspaceindia.co.in': 'Nandini',
  'narindra.kumar@interspaceindia.co.in': 'Narendra',
  'ritu.jhaveri@interspaceindia.co.in': 'Ritu',
  'steve.sequeira@interspaceindia.co.in': 'Steve Sequeira'
};

// ==== COLUMN INDEXES (1-based) ====
const COL = {
  DATE: 1,        // A
  NAME: 2,        // B
  CLIENT: 3,      // C
  DEPT: 4,        // D
  TYPE: 5,        // E
  BRIEFED_BY: 6,  // F
  START: 7,       // G
  STOP: 8,        // H
  DURATION: 9,    // I
  HOURS: 10,      // J
  UTIL: 11,       // K
  STATUS: 12,     // L
  REMARKS: 13     // M
};

// ==== MENU ====
function onOpen() {
  const ui = SpreadsheetApp.getUi();
  ui.createMenu('Time Tracker')
    .addItem('Start Timer', 'startNowPrompt')
    .addItem('Stop Timer', 'stopNow')
    .addSeparator()
    .addItem('Auto Fill Row', 'autoFillRow')
    .addItem('Force Stop Last Row (Admin)', 'forceStopLastRow')
    .addSeparator()
    .addItem('View Security Log (Admin)', 'viewSecurityLog')
    .addItem('Clear Alert Cooldowns (Admin)', 'clearAlertCooldowns')
    .addSeparator()
    .addItem('Install onEdit Trigger (Admin)', 'installOnEditTrigger')
    .addItem('Test onEdit Function (Admin)', 'testOnEditFunction')
    .addToUi();
}

// ===== ENHANCED PUBLIC FUNCTIONS =====

// Enhanced start function with validation
function startNowPrompt() {
  setLock(true);
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_NAME);
    const tz = Session.getScriptTimeZone();
    const ui = SpreadsheetApp.getUi();

    const email = Session.getActiveUser().getEmail() || '';
    const name = EMAIL_MAP[email] || email || 'Unknown';

    // Check existing open row
    const openRow = getOpenRowForUser(sheet, name);
    if (openRow) {
      ui.alert('You already have a running timer. Stop it first.');
      return;
    }

    // Get user input
    const department = chooseFromList('Department Name',
      'Select your Department by number:', DEPARTMENTS, true);
    if (department == null) return;

    const type = chooseFromList('Type', 'Select the type:', TYPE_LIST, false);
    if (type == null) return;

    const briefedBy = chooseFromList('Briefed By',
      'Select who briefed you (by number):', BRIEFED_BY_LIST, true);
    if (briefedBy == null) return;

    const clientResponse = ui.prompt("Client Name", "Enter the client name:", ui.ButtonSet.OK_CANCEL);
    if (clientResponse.getSelectedButton() !== ui.Button.OK) return;
    const client = clientResponse.getResponseText().trim();

    // Validate data
    const userData = {
      name: name,
      client: client,
      department: department,
      type: type,
      briefedBy: briefedBy
    };
    
    const validationIssues = validateTimerData(userData);
    if (validationIssues.length > 0) {
      ui.alert('Validation Error', validationIssues.join('\n'), ui.ButtonSet.OK);
      return;
    }

    // Create entry
    const today = new Date();
    const formattedDate = Utilities.formatDate(today, tz, 'dd/MM/yyyy');
    const startTime = new Date();
    const row = sheet.getLastRow() + 1;

    // Set values with proper formatting
    sheet.getRange(row, COL.DATE).setValue(formattedDate);
    sheet.getRange(row, COL.NAME).setValue(name);
    sheet.getRange(row, COL.CLIENT).setValue(client);
    sheet.getRange(row, COL.DEPT).setValue(department);
    sheet.getRange(row, COL.TYPE).setValue(type);
    sheet.getRange(row, COL.BRIEFED_BY).setValue(briefedBy);
    
    const startCell = sheet.getRange(row, COL.START);
    startCell.setValue(startTime);
    startCell.setNumberFormat('HH:mm:ss');
    
    sheet.getRange(row, COL.STOP, 1, 7).clearContent();
    sheet.getRange(row, COL.STATUS).setValue('In Progress');

    SpreadsheetApp.flush();
    ui.alert('Timer started! Row #' + row);
    
    // Log legitimate start and send alert
    logSecurityIncident('TIMER_START', {
      userEmail: email,
      userName: name,
      client: client,
      department: department,
      row: row,
      timestamp: new Date().toLocaleString()
    });
    
    // Send timer start alert to admin (NO COOLDOWN APPLIED)
    sendAdminAlert('TIMER_START', email, name, client, department, new Date().toLocaleString());
    
  } catch (err) {
    Logger.log('startNowPrompt Error: ' + err);
    SpreadsheetApp.getActiveSpreadsheet().toast('Error: ' + err.message, 'Error', 6);
  } finally {
    setLock(false);
  }
}

// Enhanced stop function with validation AND POPUP WARNING
function stopNow() {
  setLock(true);
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = ss.getSheetByName(SHEET_NAME);
    const tz = Session.getScriptTimeZone();
    const ui = SpreadsheetApp.getUi();

    const email = Session.getActiveUser().getEmail() || '';
    const name = EMAIL_MAP[email] || email || 'Unknown';
    const openRow = getOpenRowForUser(sheet, name);
    
    if (!openRow) {
      ui.alert('No running timer found for your name.');
      return;
    }

    const stopTime = new Date();
    const startTimeCell = sheet.getRange(openRow, COL.START);
    const startTime = startTimeCell.getValue();
    
    // Validate timer stop
    const validationIssues = validateTimerStop(startTime, stopTime, openRow);
    if (validationIssues.length > 0) {
      ui.alert('Timer Stop Issues', validationIssues.join('\n'), ui.ButtonSet.OK);
      // Continue with stop but log the issues
      logSecurityIncident('TIMER_VALIDATION_WARNING', {
        userEmail: email,
        userName: name,
        issues: validationIssues,
        row: openRow,
        timestamp: new Date().toLocaleString()
      });
    }

    // Set stop time
    const stopCell = sheet.getRange(openRow, COL.STOP);
    stopCell.setValue(stopTime);
    stopCell.setNumberFormat('HH:mm:ss');

    // Calculate duration and hours
    let timeDiffMs;
    if (startTime instanceof Date && stopTime instanceof Date) {
      timeDiffMs = stopTime.getTime() - startTime.getTime();
      if (timeDiffMs < 0) {
        timeDiffMs += 24 * 60 * 60 * 1000;
      }
    } else {
      const dateVal = sheet.getRange(openRow, COL.DATE).getValue();
      const startDate = toDateTime(dateVal, startTime);
      const stopDate = toDateTime(dateVal, stopTime);
      if (stopDate < startDate) stopDate.setDate(stopDate.getDate() + 1);
      timeDiffMs = stopDate - startDate;
    }

    let totalHours = timeDiffMs / (1000 * 60 * 60);
    // If duration is less than 15 minutes (0.25 hours), set totalHours to 0
    if (totalHours < 0.25) {
      totalHours = 0;
    }
    const roundedHours = Math.round(totalHours * 100) / 100;

    // NEW: Check if hours exceed 12 and show popup warning
    if (!checkAndWarnExceedingHours(roundedHours, name)) {
      // User clicked CANCEL, so revert the stop time and exit
      stopCell.clear();
      sheet.getRange(openRow, COL.STATUS).setValue('In Progress');
      SpreadsheetApp.flush();
      ui.alert('Timer stop cancelled. Please review your time entry.');
      return;
    }

    // Set calculated values
    const durationCell = sheet.getRange(openRow, COL.DURATION);
    const durationInDays = timeDiffMs / (1000 * 60 * 60 * 24);
    durationCell.setValue(durationInDays);
    durationCell.setNumberFormat('[h]:mm:ss');

    const hoursCell = sheet.getRange(openRow, COL.HOURS);
    hoursCell.setValue(roundedHours);
    hoursCell.setNumberFormat('0.00');

    const util = (roundedHours / MONTHLY_HOURS) * 100;
    const utilCell = sheet.getRange(openRow, COL.UTIL);
    utilCell.setValue(util / 100);
    utilCell.setNumberFormat('0.00%');
    
    sheet.getRange(openRow, COL.STATUS).setValue('Completed');

    SpreadsheetApp.flush();
    ui.alert(`Timer stopped! Row #${openRow}\nTotal time: ${roundedHours} hours`);
    
    // Log legitimate stop and send alert
    logSecurityIncident('TIMER_STOP', {
      userEmail: email,
      userName: name,
      hours: roundedHours,
      row: openRow,
      timestamp: new Date().toLocaleString()
    });
    
    // Send timer stop alert to admin (NO COOLDOWN APPLIED)
    sendAdminAlert('TIMER_STOP', email, name, roundedHours, new Date().toLocaleString());
    
  } catch (err) {
    Logger.log('stopNow Error: ' + err);
    SpreadsheetApp.getActiveSpreadsheet().toast('Error: ' + err.message, 'Error', 6);
  } finally {
    setLock(false);
  }
}

// Admin functions for security management
function viewSecurityLog() {
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    const logSheet = ss.getSheetByName('Security_Log');
    
    if (logSheet) {
      logSheet.showSheet();
      ss.setActiveSheet(logSheet);
      SpreadsheetApp.getActiveSpreadsheet().toast('Security log is now visible', 'Admin Access', 3);
    } else {
      SpreadsheetApp.getActiveSpreadsheet().toast('No security log found', 'Info', 3);
    }
  } catch (error) {
    SpreadsheetApp.getActiveSpreadsheet().toast('Error accessing security log: ' + error.message, 'Error', 5);
  }
}

function clearAlertCooldowns() {
  try {
    const props = PropertiesService.getScriptProperties();
    const allProps = props.getProperties();
    let clearedCount = 0;
    
    for (const key in allProps) {
      if (key.startsWith('ALERT_COOLDOWN_') || key.startsWith('SUSPICIOUS_')) {
        props.deleteProperty(key);
        clearedCount++;
      }
    }
    
    SpreadsheetApp.getActiveSpreadsheet().toast(`Cleared ${clearedCount} alert cooldowns and suspicious activity counters`, 'Admin Action', 5);
  } catch (error) {
    SpreadsheetApp.getActiveSpreadsheet().toast('Error clearing cooldowns: ' + error.message, 'Error', 5);
  }
}


// Helper function to find an open row for a given user
function getOpenRowForUser(sheet, userName) {
  const data = sheet.getDataRange().getValues();
  for (let i = data.length - 1; i >= 1; i--) { // Iterate backwards from the last row, skipping header
    const row = data[i];
    const nameInSheet = EMAIL_MAP[row[COL.NAME - 1]] || row[COL.NAME - 1];
    const status = row[COL.STATUS - 1];

    if (nameInSheet === userName && status === 'In Progress') {
      return i + 1; // Return 1-based row index
    }
  }
  return null;
}

// Helper function to let user choose from a list
function chooseFromList(title, promptText, list, allowOther) {
  const ui = SpreadsheetApp.getUi();
  let response;
  let chosenItem = null;

  while (chosenItem === null) {
    let message = promptText + '\n\n';
    for (let i = 0; i < list.length; i++) {
      message += `${i + 1}. ${list[i]}\n`;
    }
    if (allowOther) {
      message += `\nOr type your own value.`;
    }

    response = ui.prompt(title, message, ui.ButtonSet.OK_CANCEL);

    if (response.getSelectedButton() === ui.Button.OK) {
      const text = response.getResponseText().trim();
      const num = parseInt(text);

      if (!isNaN(num) && num > 0 && num <= list.length) {
        chosenItem = list[num - 1];
      } else if (allowOther && text.length > 0) {
        chosenItem = text;
      } else {
        ui.alert('Invalid selection', 'Please select a valid number or type a value.', ui.ButtonSet.OK);
      }
    } else {
      return null; // User cancelled
    }
  }
  return chosenItem;
}

// Helper function to convert date and time to DateTime object
function toDateTime(dateVal, timeVal) {
  const date = new Date(dateVal);
  const time = new Date(timeVal);
  date.setHours(time.getHours());
  date.setMinutes(time.getMinutes());
  date.setSeconds(time.getSeconds());
  return date;
}