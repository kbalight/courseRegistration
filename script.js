function toggleMenu() {
    var menu = document.getElementById("myLinks");
    var mainContent = document.querySelector("main");

    // Toggle the menu visibility
    menu.classList.toggle("show");

    // Adjust main section to move down if menu is open
    if (menu.classList.contains("show")) {
        mainContent.classList.add("menu-open");
    } else {
        mainContent.classList.remove("menu-open");
    }
}

