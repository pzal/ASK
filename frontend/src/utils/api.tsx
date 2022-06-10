import axios from 'axios'
import {useAsync} from 'react-async'

import {getApiKeyFromCookie} from './cookies'

export const _apiGet = async ({url, ...args}: any) => {
  const headers: any = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }
  // const token = getApiKeyFromCookie()
  // if (token) {
  //   headers['Authorization'] = `Token ${token}`
  // }

  return axios
    .get(url, {
      // headers,
      baseURL: process.env.REACT_APP_API_URL,
      withCredentials: true,
    })
    .then(response => response.data)
}

export const apiPost = (url: string, data: any) => {
  const headers: any = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }
  // const token = getApiKeyFromCookie()
  // if (token) {
  //   headers['Authorization'] = `Token ${token}`
  // }
  return axios.post(url, data, {
    // headers,
    baseURL: process.env.REACT_APP_API_URL,
    withCredentials: true,
  })
}

export const apiPatch = (url: string, data: any) => {
  const headers: any = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }
  const token = getApiKeyFromCookie()
  if (token) {
    headers['Authorization'] = `Token ${token}`
  }
  return axios.patch(url, data, {
    headers,
  })
}

export const apiDelete = (url: string) => {
  const headers: any = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }
  const token = getApiKeyFromCookie()
  if (token) {
    headers['Authorization'] = `Token ${token}`
  }
  return axios.delete(url, {
    headers,
  })
}

export function useApiGet<T = any>(url: string, deferred = false) {
  const callParams: any = {}
  if (deferred) {
    const deferFn = () => _apiGet({url})
    callParams['deferFn'] = deferFn
  } else {
    callParams['promiseFn'] = _apiGet
    callParams['url'] = url
  }
  interface RetValue {
    data?: T
    isPending: boolean
    isRejected: boolean
    error?: any
    reload: () => void
    run: () => void
  }
  const {data, isPending, error, isRejected, reload, run}: RetValue =
    useAsync<T>({
      ...callParams,
    })

  // const jsonData = response.data as {[key: string]: any}

  return {data, error, isPending, isRejected, reload, run}
}
