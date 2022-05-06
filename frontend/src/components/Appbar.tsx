import React from 'react'
import {Switch, Route} from 'react-router-dom'
import {makeStyles} from '@material-ui/core/styles'
import AppBar from '@material-ui/core/AppBar'
import Toolbar from '@material-ui/core/Toolbar'
import Button from '@material-ui/core/Button'
import Typography from '@material-ui/core/Typography'
import {SIDEBAR_WIDTH} from '../App'
import styled from 'styled-components'

const useStyles = makeStyles(theme => ({
  appBar: {
    width: `calc(100% - ${SIDEBAR_WIDTH}px)`,
    marginLeft: SIDEBAR_WIDTH,
  },
}))

const ToolbarContent = styled.div`
  width: 100%;
  
  display: flex;
  justify-content: space-between;
  align-items: center;
`

export default function Appbar() {
  const classes = useStyles()

  return (
    <AppBar position="fixed" className={classes.appBar}>
      <Toolbar>
        <ToolbarContent>
          <Typography variant="h6" noWrap>
            <Switch>
              <Route path="/home">Start</Route>
              <Route path="/transfers/new">Nowy przelew</Route>
              <Route path="/transfers/all">Wszystkie przelewy</Route>
              <Route path="/transfers/:transferId">Szczegóły przelewu</Route>
              <Route path="/contacts/all">Kontakty</Route>
              <Route path="/contacts/new">Nowy kontakt</Route>
              <Route path="/contacts/:contactId">Edycja kontaktu</Route>
            </Switch>
          </Typography>
        </ToolbarContent>
      </Toolbar>
    </AppBar>
  )
}
