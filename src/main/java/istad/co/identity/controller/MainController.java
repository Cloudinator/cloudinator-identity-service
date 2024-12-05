package istad.co.identity.controller;

import istad.co.identity.model.Item;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Arrays;

@Controller
public class MainController {

    @GetMapping("/")
    public String index(Model model) {
        // Add any data you want to pass to the template
        model.addAttribute("items", Arrays.asList(
                new Item("Item 1"),
                new Item("Item 2")
        ));
        return "login";
    }
}