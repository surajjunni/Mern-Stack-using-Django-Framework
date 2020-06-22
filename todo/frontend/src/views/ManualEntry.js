import React, { Component } from "react";
 
class ManualEntry extends Component {
 state = {
    manufacturer_name: '',
    model_name: '',
    ue_mac: '',
    os_type: '',
    os_version: '',
    ver_80211_support: '',
    freq_support: '',
    device_type: '',
    serial_no: '',
    release_year: '',
    priority: '', 
    chrome_ver: '',
    safari_ver: '',
    edge_ver: '',
    samsungBrowser_ver: '',
    is_sticky: '',
    TLS_ver: '', 
    is_11wC: '',
    is_PMK: '',
    is_OKC: '',
    is_11r: '',
    is_UNII_2A: '',
    is_UNII_2B: '',
    is_UNII_2C: '',
    is_11k: '',
    is_PMK_cache: '',
    is_WPA3: '',
  }

  handleChange = event => {
    this.setState({ TLS_ver: event.target.value });
  }

  handleSubmit = event => {
    event.preventDefault();
    const user = {
      manufacturer_name: this.state.manufacturer_name,
      model_name: this.state.model_name,
      ue_mac: this.state.ue_mac,
      os_type: this.state.os_type,
      os_version: this.state.os_version,
      ver_80211_support: this.state.ver_80211_support,
      freq_support: this.state.freq_support,
      device_type: this.state.device_type,
      serial_no: this.state.serial_no,
      release_year: this.state.release_year,
      priority: this.state.priority, 
      chrome_ver: this.state.chrome_ver,
      safari_ver: this.state.safari_ver,
      edge_ver: this.state.edge_ver,
      samsungBrowser_ver: this.state.samsungBrowser_ver,
      is_sticky: this.state.is_sticky,
      TLS_ver: this.state.tks_ver, 
      is_11wC: this.state.is_11wC,
      is_PMK: this.state.is_PMK,
      is_OKC: this.state.is_OKC,
      is_11r: this.state.is_11r,
      is_UNII_2A: this.state.is_UNII_2A,
      is_UNII_2B: this.state.is_UNII_2B,
      is_UNII_2C: this.state.is_UNII_2C,
      is_11k: this.state.is_11k,
      is_PMK_cache: this.state.is_PMK_cache,
      is_WPA3: this.state.is_WPA3,
      };
      
    axios({
        method: 'post',
        url: 'http://127.0.0.1:8000/',
        data: user,
        xsrfCookieName: 'csrftoken',
        xsrfHeaderName: 'X-CSRFToken',
        headers: {'X-Requested-With': 'XMLHttpRequest',
                  'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
    }).then(function (response) { 
        console.log(response);
    });
  }


  render() {
    return (
      <div>
<form  method="post" onSubmit={this.submitFormHandler} >
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Manufacturer Name</label>
    <input type="text" className="form-control" name="manufacturer_name" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Model Name</label>
    <input type="text" className="form-control" name="model_name" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Model No.</label>
    <input type="text" className="form-control" name="model_no" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">MAC</label>
    <input type="text" className="form-control" name="ue_mac" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">OS Type</label>
    <input type="text" className="form-control" name="os_type" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">OS Version</label>
    <input type="text" className="form-control" name="os_version" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">802.11 version</label>
    <input type="text" className="form-control" name="ver_80211_support" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Frequency</label>
    <input type="text" className="form-control" name="freq_support" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Device Type</label>
    <input type="text" className="form-control" name="device_type" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Serial No.</label>
    <input type="text" className="form-control" name="serial_no" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Release Year</label>
    <input type="text" className="form-control" name="release_year" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Priority</label>
    <input type="text" className="form-control" name="priority" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Chrome Version</label>
    <input type="text" className="form-control" name="chrome_ver" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Safari version</label>
    <input type="text" className="form-control" name="safari_ver" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Edge version</label>
    <input type="text" className="form-control" name="edge_ver" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">Samsung Browser version</label>
    <input type="text" className="form-control" name="samsungBrowser_ver" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <label htmlFor="exampleFormControlInput1">TLS version</label>
    <input type="text" className="form-control "name="TLS_ver" onChange={this.handleChange} />
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_sticky"onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_sticky">
        Sticky
      </label>
    </div>
  </div>
 
   <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_11wC"onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_11wC">
        is_11wC
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_PMK" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_PMK">
        PMK Support
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_OKC" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_OKC">
        OKC Support
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_11r" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_11r">
        11r support
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_11k" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_11k">
        11k support
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_PMK_cache" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_PMK_cache">
        PMK Cache
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_UNII_2A" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_UNII_2A">
        UNII_2A
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_UNII_2B" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_UNII_2B">
        UNII_2B
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_UNII_2C" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_UNII_2C">
        UNII_2C
      </label>
    </div>
  </div>
  <div className="form-group">
    <div className="form-check">
      <input className="form-check-input" type="checkbox" name="is_WPA3" onChange={this.handleChange} />
      <label className="form-check-label" htmlFor="is_WPA3">
        WPA3
      </label>
    </div>
  </div>
  <button type="submit">Submit</button>
</form>
</div>
 );
  }
}

export default ManualEntry;