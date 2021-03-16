const readline = require('readline');
const fs = require('fs');
const { exit } = require('process');

var args = process.argv.slice(2);

if (!args.length) {
    console.log("This program filters the entry points from a csv")
    console.log("Usage: node filterentrypoints.js FILENAME");
    exit(0);
}

const funcs = [];

const rl = readline.createInterface({
    input: fs.createReadStream(args[0]),
    output: process.stdout,
    terminal: false
});

rl.on('line', (line) => {
    let tokens = line.split(/,/);
    let addr = tokens[0];
    let func = tokens[1];

    if (func && addr) {
        addr = addr.replace(/^00/, "0x").toLowerCase();
        //func = func.replace(/\+.*/, "");
        if (!funcs.includes(func)) {
            //console.log(`createSymbol(toAddr(long("${addr}", 16)), "${func}_${addr}", False)`);
            //console.log(`createLabel(space.getAddress(${addr}), "${func}_${addr}", false);`);
            console.log(`${addr},${func}`);
            funcs.push(func);
        }
    }
});