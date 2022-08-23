package com.github.trganda.pocs;

import java.util.List;

public class Detail {
    public String author;
    private List<String> links;

    public Detail() {

    }

    public Detail(String author, List<String> links) {
        this.author = author;
        this.links = links;
    }

//    public String getAuthor() {
//        return author;
//    }
//
//    public void setAuthor(String author) {
//        this.author = author;
//    }

    public List<String> getLinks() {
        return links;
    }

    public void setLinks(List<String> links) {
        this.links = links;
    }

    @Override
    public String toString() {
        return "Detail{" +
                "author='" + author + '\'' +
                ", links=" + links +
                '}';
    }
}
