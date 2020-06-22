import React, { Component } from "react";
 
class AddEntry extends Component {
   state = {
    todos: []
  };

  async componentDidMount() {
    try {
      const res = await fetch('http://127.0.0.1:8000/');
      const todos = await res.json();
      this.setState({
        todos
      });
    } catch (e) {
      console.log(e);
    }
  }

  render() {
    return (
      
      <div className="container">
       <table  className="table table-sm table-dark" id="dtBasicExample">
        <thead>
    <tr >
        <th scope="col">manufacturer_name</th>
        <th scope="col">Model_Name</th>
        <th scope="col">model_no</th>
        <th scope="col">MAC</th>
        <th scope="col">OS Type</th>
        <th scope="col">os_version</th>
        <th scope="col">ver_80211_support</th>
        <th scope="col">is_WPA3</th>
    </tr>
        </thead>
        <tbody>
         {this.state.todos.map(item => (
             <tr >
        <td>{ item.manufacturer_name }</td>
        <td>{ item.model_name }</td>
        <td>{ item.model_no }</td>
        <td>{ item.ue_mac }</td>
        <td>{ item.os_type }</td>
        <td>{ item.os_version }</td>
        <td>{ item.ver_80211_support }</td>
        <td>{ item.is_WPA3.toString()}</td>
    </tr>
          
        ))}
        </tbody>
    </table>
      </div>
    );
  }
}
 
export default AddEntry;