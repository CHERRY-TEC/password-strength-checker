/* Password Strength Checker - browser analysis engine.
 *
 * Faithful JavaScript port of psc/analyzer.py so the deployed static site uses
 * the same scoring rules as the local Python application.  The password is
 * analysed in memory and never stored or transmitted.
 */
(function (global) {
  'use strict';

  var SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~";
  var COMMON_PASSWORDS = new Set([
    'password', 'password1', 'password123', 'passw0rd', 'p@ssword',
    '123456', '1234567', '12345678', '123456789', '1234567890',
    'qwerty', 'qwerty123', 'qwertyuiop', 'abc123', 'abc12345',
    'letmein', 'welcome', 'welcome1', 'admin', 'admin123',
    'iloveyou', 'monkey', 'dragon', 'sunshine', 'princess',
    'football', 'baseball', 'soccer', 'master', 'shadow',
    'superman', 'batman', 'trustno1', '654321', '111111',
    '000000', '1q2w3e4r', 'zaq12wsx', 'correcthorsebatterystaple',
    'p@ssw0rd', 'password1!', 'abcabc'
  ]);
  var LEET = { '@': 'a', '0': 'o', '1': 'i', '3': 'e', '$': 's', '!': 'i' };
  var ALPHABET_SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba'];
  var KEYBOARD_SEQUENCES = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz', '2wsx', '3edc', '0987654321'];
  var RATING_BANDS = [[20, 'Very Weak'], [40, 'Weak'], [60, 'Fair'], [80, 'Strong'], [101, 'Very Strong']];
  var GUESSES_PER_SECOND = 1.0e9;

  function charPool(password) {
    var pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    for (var i = 0; i < password.length; i++) {
      if (SPECIAL_CHARS.indexOf(password[i]) !== -1) { pool += SPECIAL_CHARS.length; break; }
    }
    return Math.max(pool, 1);
  }

  function hasSequence(password) {
    var lower = password.toLowerCase();
    var sources = ALPHABET_SEQUENCES.concat(KEYBOARD_SEQUENCES);
    for (var s = 0; s < sources.length; s++) {
      var source = sources[s];
      for (var i = 0; i <= source.length - 3; i++) {
        if (lower.indexOf(source.slice(i, i + 3)) !== -1) return true;
      }
    }
    var digits = (password.match(/[0-9]/g) || []).join('');
    for (var d = 0; d <= digits.length - 3; d++) {
      var a = parseInt(digits[d], 10), b = parseInt(digits[d + 1], 10), c = parseInt(digits[d + 2], 10);
      if ((b === a + 1 && c === b + 1) || (b === a - 1 && c === b - 1)) return true;
    }
    return false;
  }

  function repetitionRatio(password) {
    if (!password) return 0;
    var seen = new Set();
    for (var i = 0; i < password.length; i++) seen.add(password[i]);
    return (password.length - seen.size) / password.length;
  }

  function hasCommonWord(password) {
    var lowered = password.toLowerCase();
    var leeted = lowered.replace(/[@013$!]/g, function (ch) { return LEET[ch] || ch; });
    var candidates = [lowered, leeted];
    candidates.push(lowered.replace(/[0-9!?]+$/, ''));
    candidates.push(leeted.replace(/[0-9!?]+$/, ''));
    for (var i = 0; i < candidates.length; i++) {
      var candidate = candidates[i];
      if (!candidate) continue;
      if (COMMON_PASSWORDS.has(candidate)) return true;
      for (var word of COMMON_PASSWORDS) {
        if (word.length >= 6 && candidate.indexOf(word) !== -1) return true;
      }
    }
    return false;
  }

  function ratingForScore(score) {
    for (var i = 0; i < RATING_BANDS.length; i++) {
      if (score < RATING_BANDS[i][0]) return RATING_BANDS[i][1];
    }
    return 'Very Strong';
  }

  function formatDuration(seconds) {
    if (seconds < 1) return 'less than a second';
    if (seconds > 4.35e17) return 'longer than the age of the universe';
    var names = ['seconds', 'minutes', 'hours', 'days', 'years', 'thousand years'];
    var divisors = [60.0, 60.0, 24.0, 365.0, 1000.0];
    var value = seconds, index = 0, broke = false;
    for (var i = 0; i < divisors.length; i++) {
      index = i;
      if (value < divisors[i]) { broke = true; break; }
      value /= divisors[i];
    }
    if (!broke) {
      value = seconds / (60.0 * 60.0 * 24.0 * 365.0 * 1000.0);
      index = 5;
    }
    if (value >= 1000) return 'over ' + Math.floor(value).toLocaleString('en-US') + ' ' + names[index];
    return 'about ' + Math.max(1, Math.round(value)) + ' ' + names[index];
  }

  function analyzePassword(input) {
    var password = typeof input === 'string' ? input : String(input == null ? '' : input);
    var length = password.length;
    var hasUpper = /[A-Z]/.test(password);
    var hasLower = /[a-z]/.test(password);
    var hasDigit = /[0-9]/.test(password);
    var hasSpecial = false;
    for (var i = 0; i < password.length; i++) {
      if (SPECIAL_CHARS.indexOf(password[i]) !== -1) { hasSpecial = true; break; }
    }
    var charClasses = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;

    var repetition = repetitionRatio(password);
    var sequenceFound = hasSequence(password);
    var commonFound = hasCommonWord(password);

    var entropy = length * Math.log2(charPool(password));
    entropy *= (1.0 - 0.5 * repetition);
    if (sequenceFound) entropy *= 0.60;
    if (commonFound) entropy *= 0.30;
    entropy = Math.max(0, Math.round(entropy * 100) / 100);

    var guesses = Math.pow(2, entropy) / 2;
    var crackTime = guesses > 1.0e300
      ? 'longer than the age of the universe'
      : formatDuration(guesses / GUESSES_PER_SECOND);

    var effectiveLength = length * (1.0 - repetition);
    if (sequenceFound) effectiveLength *= 0.50;
    if (commonFound) effectiveLength *= 0.60;

    var lengthPoints = (Math.min(effectiveLength, 16.0) / 16.0) * 30.0;
    var classPoints = (charClasses / 4.0) * 20.0;
    var entropyPoints = (Math.min(entropy, 80.0) / 80.0) * 30.0;
    if (sequenceFound) entropyPoints *= 0.50;

    var integrity = 20.0;
    if (length === 0) integrity = 0.0;
    else if (length < 4) integrity -= 12.0;
    else if (length < 8) integrity -= 6.0;
    if (commonFound) integrity -= 12.0;
    if (sequenceFound) integrity -= 10.0;
    if (repetition > 0.30) integrity -= 12.0;
    if (charClasses >= 3) integrity += 2.0;
    if (length >= 12) integrity += 2.0;
    integrity = Math.max(0, Math.min(20, integrity));

    var score = Math.max(0, Math.min(100,
      Math.round(lengthPoints + classPoints + entropyPoints + integrity)));

    var issues = [], suggestions = [];
    if (length === 0) {
      issues.push('Empty password');
      suggestions.push('Choose a password with at least 12 characters.');
    } else {
      if (length < 8) {
        issues.push('Too short (' + length + (length === 1 ? ' character' : ' characters') + '; 12+ recommended)');
        suggestions.push('Use at least 12 characters.');
      } else if (length < 12) {
        suggestions.push('Aim for 12 or more characters for better resilience.');
      }
      if (charClasses < 3) {
        issues.push('Only ' + charClasses + ' character type(s) used');
        suggestions.push('Mix uppercase, lowercase, digits and symbols.');
      }
      if (!hasUpper) suggestions.push('Add at least one uppercase letter.');
      if (!hasLower) suggestions.push('Add at least one lowercase letter.');
      if (!hasDigit) suggestions.push('Add at least one digit.');
      if (!hasSpecial) suggestions.push('Add at least one symbol (e.g. ! @ # $).');
      if (commonFound) {
        issues.push('Matches or contains a common password / dictionary word');
        suggestions.push('Avoid common words and well-known passwords.');
      }
      if (sequenceFound) {
        issues.push('Contains a character sequence or keyboard pattern');
        suggestions.push('Avoid sequences such as 123, abc or qwerty.');
      }
      if (repetition > 0.30) {
        issues.push('High character repetition (' + Math.round(repetition * 100) + '%)');
        suggestions.push('Avoid repeated characters.');
      }
    }
    if (!issues.length) suggestions.push('Good work! Use a unique password for each account.');

    return {
      score: score,
      rating: ratingForScore(score),
      length: length,
      has_upper: hasUpper,
      has_lower: hasLower,
      has_digit: hasDigit,
      has_special: hasSpecial,
      char_classes: charClasses,
      entropy_bits: entropy,
      crack_time: crackTime,
      issues: issues,
      suggestions: suggestions.slice(0, 6)
    };
  }

  function explainRules() {
    return [
      { title: 'Length', rule: 'Use at least 12 characters; longer is stronger.', why: 'Every extra character multiplies the number of possible combinations.' },
      { title: 'Character variety', rule: 'Mix uppercase letters, lowercase letters, digits and symbols.', why: 'A larger character pool makes brute-force guesses far more expensive.' },
      { title: 'Avoid common passwords', rule: "Never use dictionary words, names or passwords like 'password123'.", why: 'Attackers try these first using wordlists of leaked passwords.' },
      { title: 'Avoid patterns', rule: 'Skip sequences such as 1234, abcd and qwerty.', why: 'Predictable ordering dramatically reduces the search space.' },
      { title: 'Avoid repetition', rule: 'Do not repeat the same character many times.', why: 'Repetition lowers real entropy even when a password looks long.' },
      { title: 'Uniqueness', rule: 'Use a different password for every account.', why: 'One leaked site should not compromise all of your accounts.' },
      { title: 'Local processing', rule: 'This tool analyses passwords in your browser and stores only result metadata.', why: 'Your password is never written to disk or sent anywhere.' }
    ];
  }

  var SAMPLE_DATA = [
    ['Campus WiFi guest', 'password'], ['Old library card', '123456'],
    ['Dorm router', 'qwerty'], ['Club signup', 'abc123'],
    ['Lab workstation', 'letmein'], ['Alumni portal', 'welcome1'],
    ['Admin console', 'admin'], ['Print kiosk', '111111'],
    ['Shared calendar', 'sunshine'], ['Sports forum', 'football'],
    ['Music account', 'iloveyou'], ['Guest laptop', 'dragon'],
    ['Weather app', 'monkey'], ['Course forum', 'student1'],
    ['Library catalogue', 'Library2024'], ['Email backup', 'Summer2023!'],
    ['Cloud drive', 'P@ssw0rd'], ['Banking demo', 'Tr0ub4dor&3'],
    ['Research wiki', 'Science#2024'], ['Dev repository', 'GitPush!42'],
    ['VPN client', 'Blue$Sky77'], ['Phone hotspot', 'Mobil3Data!'],
    ['Gaming account', 'DragonSlayer99'], ['Photo storage', 'Sunset@2024'],
    ['Notebook app', 'Notes4Me!'], ['Messaging app', 'Chat_Now_24'],
    ['Shopping cart', 'BuyIt#2024'], ['Fitness tracker', 'Run5K_Miles!'],
    ['Recipe box', 'Cook@Home1'], ['Travel planner', 'Trip2024!go'],
    ['Personal wiki', 'correct horse battery staple'], ['Password manager', 'X9#mL2@vT7!qR4$p'],
    ['Server SSH key', 'vL8!qZ#2wR@6tY&1c'], ['Encryption test', 'Zx7!Qp9#Lm2@Wn5$'],
    ['Security audit', 'A1!b2@C3#D4$e5%'], ['Strong passphrase', 'Purple-Coffee-Mountain-42'],
    ['Boundary: single char', 'a'], ['Boundary: two chars', 'a1'],
    ['Boundary: eight chars', 'Abcdefg1'], ['Edge: empty password', ''],
    ['Edge: repeated chars', 'aaaaaaaaaaaaaaaaaaaa'], ['Edge: repeated pair', 'abababababababab'],
    ['Edge: alphabet run', 'abcdefghijklmnop'], ['Edge: number run', '1234567890123456'],
    ['Edge: keyboard walk', 'qwertyuiop123'], ['Edge: padded common', '!!password123!!']
  ];

  global.Analyzer = {
    analyzePassword: analyzePassword,
    explainRules: explainRules,
    SAMPLE_DATA: SAMPLE_DATA
  };
})(window);
