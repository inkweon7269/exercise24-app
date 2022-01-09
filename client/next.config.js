const withAntdLess = require('next-plugin-antd-less');

module.exports = withAntdLess({
  lessVarsFilePath: './src/styles/variables.less',
  lessVarsFilePathAppendToEndOfContent: false,
  cssLoaderOptions: {},

  webpack(config) {
    return config;
  },
});