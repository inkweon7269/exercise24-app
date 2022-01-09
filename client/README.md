### 1. Next.js + TypeScript 설치
```bash
npx create-next-app --typescript [project name]

npm run dev
# or
yarn dev
```

### 2. Styled-Components 설치
```bash
npm install styled-components
npm install -D @types/styled-components babel-plugin-styled-components
```
설치가 완료되면 최상위 디렉토리에 .babelrc 파일을 추가한 후 다음 코드를 작성한다.
```json
{
  "presets": ["next/babel"],
  "plugins": [
    ["styled-components", { "ssr": true, "displayName": true, "preprocess": false }]
  ]
}
```

### 3. Styled-Components 초기 세팅

Next.js에서는 Styled-Components가 렌더링시 적용이 안되는 버그가 존재한다. 이는 초기에 렌더링 될 때 SSR로 렌더링되어서 발생하는 문제이다.   
이러한 버그는 `pages/_document.tsx` 파일을 생성하여 다음 코드를 작성하면 해결할 수 있다. 참고로 _document.tsx 파일은 SSR 렌더링할 때만 호출된다.

```typescript jsx
import Document, {
    Html,
    Head,
    Main,
    NextScript,
    DocumentContext,
} from "next/document";
import {ServerStyleSheet} from "styled-components";

export default class MyDocument extends Document {
    static async getInitialProps(ctx: DocumentContext) {
        const sheet = new ServerStyleSheet();
        const originalRenderPage = ctx.renderPage;

        try {
            ctx.renderPage = () =>
                originalRenderPage({
                    enhanceApp: (App) => (props) =>
                        sheet.collectStyles(<App {...props} />),
                })

            const initialProps = await Document.getInitialProps(ctx)
            return {
                ...initialProps,
                styles: (
                    <>
                        {initialProps.styles}
                        {sheet.getStyleElement()}
                    </>
                ),
            }
        } finally {
            sheet.seal()
        }
    }
}
```
Styled-Components를 사용하여 공통 CSS를 적용하고 싶다면 `pages/_app.tsx` 파일 안에 다음 코드를 작성한다.
```typescript jsx
import type {AppProps} from 'next/app'
import { createGlobalStyle, ThemeProvider } from "styled-components";

const theme: any = {}

const GlobalStyle = createGlobalStyle`
    body {
      background-color: yellow;
    }
`;

function MyApp({Component, pageProps}: AppProps) {
    return (
        <>
            <GlobalStyle />

            <ThemeProvider theme={theme}>
                <Component {...pageProps} />
            </ThemeProvider>
        </>
    )
}

export default MyApp
```

### 4. Ant Design 설치
```bash
npm install antd next-plugin-antd-less
npm i -D babel-plugin-import
```
기존 CSS 변수값을 변경하기 위해서는 `src/styles/variables.less` 파일 생성 후 다음 코드를 작성한다.
```less
@import '~antd/lib/style/themes/default.less';
@primary-color: #04f;
```
Ant Desige의 less파일이 정착(?)될 수 있도록 `next.config.js` 파일의 설정을 변경한다.
```js
const withAntdLess = require('next-plugin-antd-less');

module.exports = withAntdLess({
    lessVarsFilePath: './src/styles/variables.less',
    lessVarsFilePathAppendToEndOfContent: false,
    cssLoaderOptions: {},

    webpack(config) {
        return config;
    },
});
```
마지막으로 `.babelrc` 파일 안에 antd를 추가한다.
```json
{
  "presets": ["next/babel"],
  "plugins": [
    ["import", { "libraryName": "antd", "style": true }],
    ["styled-components", { "ssr": true, "displayName": true, "preprocess": false }]
  ]
}
```