import React from 'react'
import {Switch, Route} from 'react-router-dom'
import {makeStyles} from '@material-ui/core/styles'
import AppBar from '@material-ui/core/AppBar'
import Toolbar from '@material-ui/core/Toolbar'
import Button from '@material-ui/core/Button'
import Typography from '@material-ui/core/Typography'
import {SIDEBAR_WIDTH} from '../App'
import styled from 'styled-components'
import {setApiKeyInCookie} from '../utils/cookies'
import {useApiGet} from '../utils/api'
import CircularProgress from '@material-ui/core/CircularProgress'
import IconButton from '@material-ui/core/IconButton'
import ExitToAppIcon from '@material-ui/icons/ExitToApp'

const useStyles = makeStyles(theme => ({
  appBar: {
    width: `calc(100% - ${SIDEBAR_WIDTH}px)`,
    marginLeft: SIDEBAR_WIDTH,
  },
}))

const UserDetailsWrapper = styled.div`
  > div {
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  padding: 0.5rem;
  padding-bottom: 1.5rem;
`

const Avatar = styled.div`
  height: 50px;
  width: 50px;
  border-radius: 50%;
  background: green;
  color: white;
  display: flex;
  justify-content: center;
  align-items: center;

  span {
    font-size: 1.2rem;
    text-transform: uppercase;
  }
`
const Email = styled.div`
  color: grey;
`
const Balance = styled.div`
  margin-top: 0.5rem;

  div {
    margin-bottom: 0.4rem;
  }

  span {
    font-weight: bold;
  }
`

interface Account {
  id: string
  account_number: string
  balance: any
}

interface Me {
  id: any
  email: string
  account_set: Account[]
}

export default function UserDetails() {
  const {data, isPending} = useApiGet<Me>(
    `${process.env.REACT_APP_API_URL}/users/me/`,
  )
  const classes = useStyles()

  const logout = () => {
    console.log('logging out')
    setApiKeyInCookie(undefined)
  }

  if (isPending) {
    return null
  }

  console.log('got me data', data)

  return (
    <UserDetailsWrapper>
      <div>
        <Avatar>
          <span>{data?.email[0]}</span>
        </Avatar>
      </div>
      <div>
        <Email>
          {data?.email}
          <IconButton onClick={logout} color="default">
            <ExitToAppIcon />
          </IconButton>
        </Email>
        <Balance>
          <div>
            Stan konta: <span>{data?.account_set[0].balance}</span>
          </div>
          <div>Nr konta: {data?.account_set[0].account_number}</div>
        </Balance>
      </div>
      <div></div>
    </UserDetailsWrapper>
  )
}
