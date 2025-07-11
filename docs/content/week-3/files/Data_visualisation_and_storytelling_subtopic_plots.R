setwd("~/Documents/Archives/G. Edinburgh post-doc/MSc Data Science Course")
library(tidyverse)
library(readxl)
library(ggpubr)
library(NHSRdatasets)
library(lubridate)
library(gapminder)
require(maps)
require(viridis)
require(VennDiagram)

data(ons_mortality)

ggplot(ons_mortality %>% 
         filter(category_1=="All respiratory diseases (ICD-10 J00-J99) ICD-10" &
                  category_2=="v 2010" &
                  year(date)==2011)) + 
  geom_line(aes(x=week_no, y=counts)) +
  theme_bw() + xlab("Week of Year (2011)") + ylab("Respiratory Deaths") +
  scale_x_continuous(limits=c(1,53), 
                     breaks=c(1,5,10,15,20,25,30,35,40,45,50,52)) +
  scale_y_continuous(limits=c(0,3000)) +
  ggtitle("Figure A: Respiratory Deaths in the UK in 2011")

ggplot(ons_mortality %>% 
         group_by(category_1,category_2) %>% 
         summarise(count = sum(counts)) %>% 
         filter(category_1=="Persons" & 
                  category_2 %in% c("65-74","75-84","85+")) %>%
         mutate(Percent = round(count*100/sum(count))), 
       aes(x="", y=Percent, fill=category_2))+
  geom_bar(width = 1, stat = "identity") +  
  theme(axis.text.x=element_blank(),
        axis.title.x = element_blank(),
        axis.title.y = element_blank(),
        panel.border = element_blank(),
        panel.background = element_blank(),
        panel.grid=element_blank(),
        axis.ticks = element_blank(),
        plot.title=element_text(size=14, face="bold")) +
  coord_polar("y", start=0) +
  geom_text(aes(y = c(90,60,20), 
                label = paste0(Percent,"%"))) +
  labs(fill="Age Category") + 
  ggtitle("Figure B: Deaths by Age Category")


data(gapminder, package = "gapminder")
world_map <- map_data("world") %>%
  rename(country=region) %>%
  mutate(TEMP = 1) %>%
  full_join(gapminder %>% 
              filter(year==2002) %>%
               select(country,lifeExp) %>%
              mutate(country = recode(country,
                                     "United States"    = "USA",
                                     "United Kingdom"    = "UK",
                                     "Cote d'Ivoire" = "Ivory Coast",
                                     "Congo, Dem. Rep." = "Democratic Republic of the Congo",
                                     "Congo, Rep."      = "Republic of Congo",
                                     "Korea, Dem. Rep." = "South Korea",
                                     "Korea. Rep."      = "North Korea",
                                     "Slovak Republic"  = "Slovakia",
                                     "Yemen, Rep."      = "Yemen"))) %>%
  ungroup()

ggplot(world_map,aes(x = long, y = lat, group=group)) +
  geom_polygon(aes(fill = lifeExp)) +
  scale_fill_viridis_c()  +
  ggtitle("Figure C: World Life Expectancy (2002)")  +
  labs(fill="Life \nExpectancy")



data(stranded_data)

stranded_data<-stranded_data %>% mutate(ID = row_number())
y<-list(
  stranded_data %>% filter(care.home.referral==1) %>% select(ID) %>% unlist(), 
  stranded_data %>% filter(hcop==1)  %>% select(ID) %>% unlist(), 
  stranded_data %>% filter(mental_health_care==1)%>% select(ID) %>% unlist())


venn.diagram(x = y,
  category.names = c("Referral from \nCare Home" , 
                     "Triaged from \nHCOP" , 
                     "Mental Health \n Support"),
  filename = 'venn.png',
  output = TRUE ,
  imagetype="png" ,
  height = 480 , 
  width = 480 , 
  resolution = 300,
  col=c("#440154ff", '#21908dff', '#fde725ff'),
  fill = c(alpha("#440154ff",0.3), alpha('#21908dff',0.3), alpha('#fde725ff',0.3)),
  cex = 0.5,
  cat.default.pos = "outer",
  cat.pos = c(-25, 30, 135),
  cat.dist = c(0.12, 0.1, 0.12),
  fontfamily = "sans",
  cat.cex = 0.5,
  cat.fontfamily = "sans")
