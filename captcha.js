export function generateCaptcha(difficulty = 'medium') {
  const difficulties = {
    easy: { types: ['addition', 'subtraction'], range: [1, 10] },
    medium: { types: ['addition', 'subtraction', 'multiplication', 'numberToText'], range: [1, 15] },
    hard: { types: ['multiplication', 'simpleAlgebra', 'mixedOperations', 'wordProblem'], range: [1, 20] },
    extreme: { types: ['complexAlgebra', 'multipleOperations', 'logicPuzzle'], range: [5, 30] }
  };

  const config = difficulties[difficulty] || difficulties.medium;
  const type = config.types[Math.floor(Math.random() * config.types.length)];
  
  let question, answer;

  switch (type) {
    case 'mixedOperations':
      const ops = ['+', '-', '*'];
      const op = ops[Math.floor(Math.random() * ops.length)];
      const num1 = randomInRange(config.range);
      const num2 = randomInRange(config.range);
      question = `Calculate: ${num1} ${op} ${num2}`;
      answer = eval(`${num1} ${op === '*' ? '*' : op} ${num2}`);
      break;

    case 'wordProblem':
      const problems = [
        { q: "If you have {a} apples and buy {b} more, how many do you have?", a: (a, b) => a + b },
        { q: "A pizza has {a} slices. If you eat {b}, how many remain?", a: (a, b) => a - b },
        { q: "There are {a} cars with {b} wheels each. Total wheels?", a: (a, b) => a * b }
      ];
      const problem = problems[Math.floor(Math.random() * problems.length)];
      const pA = randomInRange([2, 10]);
      const pB = randomInRange([2, 10]);
      question = problem.q.replace('{a}', pA).replace('{b}', pB);
      answer = problem.a(pA, pB);
      break;

    case 'complexAlgebra':
      const coeff = randomInRange([2, 5]);
      const constant = randomInRange([1, 10]);
      const result = coeff * randomInRange([3, 8]) + constant;
      question = `Solve for x: ${coeff}x + ${constant} = ${result}`;
      answer = (result - constant) / coeff;
      break;

    case 'logicPuzzle':
      const puzzles = [
        { q: "What is the next number: 2, 4, 6, 8, ?", a: 10 },
        { q: "If 3 cats catch 3 mice in 3 minutes, how many cats to catch 100 mice in 100 minutes?", a: 3 }
      ];
      const puzzle = puzzles[Math.floor(Math.random() * puzzles.length)];
      question = puzzle.q;
      answer = puzzle.a;
      break;

    default:
      return generateBasicCaptcha(type, config.range);
  }

  question = applyDistortion(question, difficulty);
  return { question, answer: Math.round(answer), type, difficulty };
}

function generateBasicCaptcha(type, range) {
  const [min, max] = range;
  const a = randomInRange(range);
  const b = randomInRange(range);

  switch (type) {
    case 'addition':
      return { question: `What is ${a} + ${b}?`, answer: a + b };
    case 'subtraction':
      const x = Math.max(a, b);
      const y = Math.min(a, b);
      return { question: `What is ${x} - ${y}?`, answer: x - y };
    case 'multiplication':
      return { question: `What is ${a} × ${b}?`, answer: a * b };
    case 'numberToText':
      const numbers = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten'];
      const num = randomInRange([0, 10]);
      return { question: `Type the number: "${numbers[num]}"`, answer: num };
    default:
      return { question: `What is ${a} + ${b}?`, answer: a + b };
  }
}

function randomInRange([min, max]) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function applyDistortion(text, difficulty) {
  const distortions = {
    easy: ['spaces'],
    medium: ['spaces', 'caps'],
    hard: ['spaces', 'caps', 'punctuation', 'leetspeak'],
    extreme: ['spaces', 'caps', 'punctuation', 'leetspeak', 'unicode']
  };

  const selectedDistortions = distortions[difficulty] || distortions.medium;
  
  return selectedDistortions.reduce((result, distortion) => {
    switch (distortion) {
      case 'leetspeak':
        return result.replace(/[aeios]/gi, char => {
          const leetMap = { 'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5' };
          return Math.random() < 0.3 ? leetMap[char.toLowerCase()] || char : char;
        });
      case 'unicode':
        return result.split('').map(char => 
          Math.random() < 0.1 ? char + String.fromCodePoint(0x200B) : char
        ).join('');
      default:
        return result;
    }
  }, text);
}

export function validateCaptchaInput(input) {
  if (input === null || input === undefined) return false;
  const num = parseInt(input);
  return !isNaN(num) && num >= 0 && num <= 1000;
}
