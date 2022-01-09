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