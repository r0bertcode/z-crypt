const URL = 'https://github.com/r0bertcode/cryptic-js';
const errors = {
  noParam: (name, param) => {
    throw new Error(`@ ${name}: Missing param ${param} | example usage @ ${URL} | ;
    `);
  },
};


module.exports = errors;
