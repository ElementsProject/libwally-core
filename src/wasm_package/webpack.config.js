import webpack from 'webpack'
import path from 'path'

export default {
    entry: './index.js',
    experiments: {
        topLevelAwait: true,
    },
    output: {
        path: path.resolve('browser-dist'),
        filename: 'wallycore.bundle.js',
        library: {
            type: 'var',
            name: 'WallyInit'
        }
    },
    resolve: {
        fallback: {
            module: false, // used within an if (NODEJS_ENV), can be skipped for browsers
            assert: './browser/assert.js',
        },
    },
    plugins: [
        new webpack.ProvidePlugin({
            Buffer: ['buffer', 'Buffer'],
        })
    ]
}