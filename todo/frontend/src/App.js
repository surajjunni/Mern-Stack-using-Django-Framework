import React from "react";
import {
  BrowserRouter as Router,
  Switch,
  Route,
  Link
} from "react-router-dom";
import AddEntry from './views/AddEntry.js';
import ExcelEntry from './views/ExcelEntry.js';
import ManualEntry from './views/ManualEntry.js';

const Routes = () => (
    <Router>
        <div>
            <ul>
                <li><Link to="/AddEntry">About Link</Link></li>
                <li><Link to="/ManualEntry">Company Link</Link></li>
                 <li><Link to="/ExcelEntry">Company Link</Link></li>
            </ul>
            <Switch>
                <Route path="/AddEntry" component={AddEntry} />
                <Route path="/ManualEntry" component={ManualEntry} />
                <Route path="/ExcelEntry" component={ExcelEntry} />
            </Switch>
        </div>
    </Router>
);

class App extends React.Component {
    render() {
        return (
                <Routes />          
        );
    }
}

export default App;