import webpack from 'webpack'
import path from 'path'

export default {
    entry: './src/index.js',
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
    plugins: [
        new webpack.ProvidePlugin({
            Buffer: ['buffer', 'Buffer'],
        })
    ]
}
