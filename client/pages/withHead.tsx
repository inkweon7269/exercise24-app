import { FC } from 'react'
import Head from 'next/head'

const withHead = (Component: FC, title?: string, url?: string) => {
    const defaultTitle: string = '우리집'
    const defaultDescription: string = '우리집'
    const defaultKeywords: string = '우리집'
    const defaultOgImage: string = ''
    const defaultOgImageWidth: string = '1200'
    const defaultOgImageHeight: string = '630'
    const defaultUrl: string = ''

    const HeadComponent: FC = (props) => {

        return (
            <>
                <Head>
                    <meta charSet="UTF-8" />
                    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=0" />
                    <title>{title || defaultTitle}</title>
                    <meta name="description" content={defaultDescription} />
                    <meta name="keywords" content={defaultKeywords} />
                    <link rel="canonical" href={url || defaultUrl}></link>
                    <link rel="shortcut icon" sizes="192x192" href="/favicon.ico" />
                    <meta property="og:type" content="website" />
                    <meta property="og:site_name" content={"세컨드 히어로"} />
                    <meta property="og:url" content={url || defaultUrl} />
                    <meta property="og:title" content={title || defaultTitle} />
                    <meta property="og:description" content={defaultDescription}/>
                    <meta name="twitter:site" content={url || defaultUrl} />
                    <meta name="twitter:card" content="summary_large_image" />
                    <meta name="twitter:image" content={defaultOgImage} />
                    <meta property="og:image" content={defaultOgImage} />
                    <meta property="og:image:width" content={defaultOgImageWidth} />
                    <meta property="og:image:height" content={defaultOgImageHeight} />
                    <link rel="preconnect" href="https://fonts.gstatic.com" />
                    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/gh/moonspam/NanumBarunGothic@latest/nanumbarungothicsubset.css" />
                </Head>
                <Component {...props} />
            </>
        )
    }
    return HeadComponent
}

export default withHead