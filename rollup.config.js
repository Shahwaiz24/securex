import typescript from '@rollup/plugin-typescript';

export default {
    input: 'src/index.ts',
    output: {
        dir: 'dist',
        format: 'es',
        name: 'securex',
    },
    external: [
        '@noble/ciphers/aes',
        '@noble/ciphers/webcrypto',
        '@noble/ciphers/crypto',
        '@noble/ciphers/utils'
    ],
    plugins: [
        typescript({
            tsconfig: 'tsconfig.json',
        }),
    ],
}