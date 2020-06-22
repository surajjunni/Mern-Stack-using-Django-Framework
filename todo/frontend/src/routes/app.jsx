import AddEntry from "./views/AddEntry.js";
import ExcelEntry from "./views/ExcelEntry.js";
import ManualEntry from "./views/ManualEntry.js";

import {
    Dashboard, Person, ContentPaste, LibraryBooks, BubbleChart, LocationOn, Notifications
} from 'material-ui-icons';

const appRoutes = [
    { path: "/AddEntry", sidebarName: "AddEntry", navbarName: "AddEntry", icon: Person, component: AddEntry },
    { path: "/ExcelEntry", sidebarName: "ExcelEntry", navbarName: "ExcelEntry", icon: ContentPaste, component: ExcelEntry },
    { path: "/ManualEntry", sidebarName: "ManualEntry", navbarName: "ManualEntry", icon: LibraryBooks, component: ManualEntry },
    { redirect: true, path: "/", to: "/ManualEntry", navbarName: "Redirect" }
];

export default appRoutes;
