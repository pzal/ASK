import React, {Fragment} from 'react'
import {Link} from 'react-router-dom'
import List from '@material-ui/core/List'
import Divider from '@material-ui/core/Divider'
import ListItem from '@material-ui/core/ListItem'
import ListItemIcon from '@material-ui/core/ListItemIcon'
import ListItemText from '@material-ui/core/ListItemText'
import AddBoxIcon from '@material-ui/icons/AddBox'
import ContactsIcon from '@material-ui/icons/Contacts'
import ListIcon from '@material-ui/icons/ViewList'

export default function NavigationLinks() {
  return (
    <Fragment>
      <List>
        <Link to="/transfers/new">
          <ListItem button>
            <ListItemIcon>
              <AddBoxIcon />
            </ListItemIcon>
            <ListItemText primary="Nowy przelew" />
          </ListItem>
        </Link>
      </List>
      <Divider />
      <List>
        <Link to="/transfers/all">
          <ListItem button>
            <ListItemIcon>
              <ListIcon />
            </ListItemIcon>
            <ListItemText primary="Wszystkie przelewy" />
          </ListItem>
        </Link>
        <Link to="/contacts/all">
          <ListItem button>
            <ListItemIcon>
              <ContactsIcon />
            </ListItemIcon>
            <ListItemText primary="Kontakty" />
          </ListItem>
        </Link>
      </List>
    </Fragment>
  )
}
