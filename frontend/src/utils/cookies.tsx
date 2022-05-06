import {useEffect, useState} from 'react'
import Cookies, {
  CookieChangeListener,
  CookieChangeOptions,
} from 'universal-cookie'
import {DateTime} from 'luxon'
const cookies = new Cookies()

const domain = undefined

export const API_KEY_COOKIE = 'apiKey'
export const EMAIL_COOKIE = 'email'

export const getApiKeyFromCookie = () => {
  // @ts-ignore
  return cookies.get(API_KEY_COOKIE, {path: '/', domain})
}

export const setApiKeyInCookie = (apiKey?: string) => {
  // if we don't set "expires", the cookie is a session cookie by default
  if (!apiKey) {
    console.log('yes removing for sure')
    cookies.remove(API_KEY_COOKIE, {
      path: '/',
      domain,
    })
  } else {
    cookies.set(API_KEY_COOKIE, apiKey, {
      path: '/',
      domain,
    })
  }
}

export const getEmailFromCookie = () => {
  // @ts-ignore
  return cookies.get(EMAIL_COOKIE, {path: '/', domain})
}

export const setEmailInCookie = (email?: string) => {
  if (!email) {
    cookies.remove(EMAIL_COOKIE)
  } else {
    // if we don't set "expires", the cookie is a session cookie by default
    cookies.set(EMAIL_COOKIE, email, {
      path: '/',
      expires: DateTime.local().plus({days: 14}).toJSDate(),
      domain,
    })
  }
}

export const useCookie = (cookieName: string) => {
  // @ts-ignore
  const initialValue = cookies.get(cookieName, {path: '/', domain})
  const [value, setValue] = useState(initialValue)

  const listener: CookieChangeListener = ({
    name,
    value,
  }: CookieChangeOptions) => {
    if (name === cookieName) {
      setValue(value)
    }
  }

  useEffect(() => {
    cookies.addChangeListener(listener)

    return () => {
      cookies.removeChangeListener(listener)
    }
  }, [])

  return value
}
