import React, {useState} from 'react'
import {Link} from 'react-router-dom'
import Appbar from './components/Appbar'
import {makeStyles} from '@material-ui/core/styles'
import Drawer from '@material-ui/core/Drawer'
import CssBaseline from '@material-ui/core/CssBaseline'
import Divider from '@material-ui/core/Divider'
import styled from 'styled-components'
import NavigationLinks from './components/NavigationLinks'
import PageRoutes from './components/PageRoutes'
import LoginPage from './pages/LoginPage'
import {useCookie, API_KEY_COOKIE, setApiKeyInCookie} from './utils/cookies'
import {useApiGet} from './utils/api'
import UserDetails from './components/UserDetails'

const BrandName = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;

  a {
    font-size: 1.6rem;
    font-weight: 700;

    color: rgb(88, 85, 116);
  }
`

export const SIDEBAR_WIDTH = 240

const useStyles = makeStyles(theme => ({
  root: {
    display: 'flex',
  },
  appBar: {
    width: `calc(100% - ${SIDEBAR_WIDTH}px)`,
    marginLeft: SIDEBAR_WIDTH,
  },
  drawer: {
    width: SIDEBAR_WIDTH,
    flexShrink: 0,
  },
  drawerPaper: {
    width: SIDEBAR_WIDTH,
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
  },
  // necessary for content to be below app bar
  toolbar: theme.mixins.toolbar,
  content: {
    flexGrow: 1,
    backgroundColor: theme.palette.background.default,
    padding: theme.spacing(3),
  },
}))

enum AUTH_STATE {
  LOGGED_IN,
  LOGGED_OUT,
  UNSURE,
}

function App() {
  const [authState, setAuthState] = useState(AUTH_STATE.UNSURE)
  const apiKey = useCookie(API_KEY_COOKIE)
  const classes = useStyles()

  const {data, error, isRejected, run} = useApiGet(
    `${process.env.REACT_APP_API_URL}/users/me/`,
    // Deferred so that we don't fire again
    // when we get `apiKey` for the first time.
    true,
  )

  React.useEffect(() => {
    if (apiKey) {
      // Potentially logged in, but we have to check if it's valid.

      if (authState === AUTH_STATE.LOGGED_OUT) {
        // Means we have been at the login screen.
        // So the token pretty much must be valid.
        setAuthState(AUTH_STATE.LOGGED_IN)
      } else {
        // Let's see if we get any client for that token.
        console.log('Reloading app: checking if new apiKey allows us to login.')
        run()
      }
    } else {
      // No apiKey, no chance.
      setAuthState(AUTH_STATE.LOGGED_OUT)
    }
  }, [apiKey])

  React.useEffect(() => {
    console.log('got data', data, error, isRejected)

    // If some response, check if it actually returned any client.
    if (data) {
      authState !== AUTH_STATE.LOGGED_IN && setAuthState(AUTH_STATE.LOGGED_IN)
    } else if (error) {
      setApiKeyInCookie(undefined)
    }
  }, [data, error])

  React.useEffect(() => {
    if (isRejected) {
      authState !== AUTH_STATE.LOGGED_OUT && setAuthState(AUTH_STATE.LOGGED_OUT)
      setApiKeyInCookie(undefined)
    }
  }, [isRejected])

  if (authState === AUTH_STATE.UNSURE) {
    return null
  }

  if (authState !== AUTH_STATE.LOGGED_IN) {
    return <LoginPage />
  }

  return (
    <div className={classes.root}>
      <CssBaseline />
      <Drawer
        className={classes.drawer}
        variant="permanent"
        classes={{
          paper: classes.drawerPaper,
        }}
        anchor="left"
      >
        <div>
          <BrandName className={classes.toolbar}>
            <Link to="/home">Bank</Link>
          </BrandName>
          <Divider />
          <NavigationLinks />
        </div>
        <div>
          <UserDetails />
        </div>
      </Drawer>
      <Appbar />
      <main className={classes.content}>
        <div className={classes.toolbar} />
        <PageRoutes />
      </main>
    </div>
  )
}

export default App
